# #469 Blocker 1 — one canonical environment-resolution path

**Status:** design (approved to draft, pending user spec-review). Branch
`469-blocker1-environment-resolution`. Parent epic: #469 (first-run experience —
a documented quickstart that actually boots). This spec covers **Blocker 1 only**.

## Problem

`alfred daemon start` refuses to boot with:

> Settings.environment is not set. Refusing to boot — production refuses without
> an explicit environment. Set ALFRED_ENVIRONMENT to one of: development,
> production, test (**in your .env**) …

…even when the operator has set `ALFRED_ENVIRONMENT` in `.env` exactly as the
message instructs. The operator does the named remedy, re-runs, and hits the
byte-identical refusal — unrecoverable without reading source.

## Root cause (reproduced)

The daemon boot gate `_load_settings_or_die()` (`cli/daemon/_commands.py:346`)
calls the standalone `load_environment()` (`config/_environment_loader.py`),
which reads **only** `os.environ["ALFRED_ENVIRONMENT"]` and
`/etc/alfred/environment`. It refuses **before** `Settings()` is constructed. But
`Settings` (pydantic-settings, `env_file=".env"`) **does** read `.env`.

Reproduction (verified): with `ALFRED_ENVIRONMENT=production` in a `.env` file and
absent from `os.environ`, `load_environment()` returns `value=None` (→ refusal)
while `Settings()` in the same run resolves `environment='production'` straight
from `.env`. So the pre-Settings gate is a **less-capable, `.env`-blind duplicate**
of what `Settings` already does.

In the compose happy-path this is masked (compose forwards `.env` → container
`os.environ` via `${ALFRED_ENVIRONMENT:-production}`), but the documented **host
path** (`alfred daemon start`) and any `.env`-only setup stay broken. A separate
compose-forward gap (no `env_file`/env-forward on `alfred-core`) was already fixed by
the PR2b-golive cutover (#340); this residual — the `.env`-blindness of the resolution
path — was deliberately left to this epic.

## The trust-precedence constraint (why not "just let Settings resolve it")

`environment` is **security-load-bearing**: `environment == "production"` gates the
sec-002 refusal (refuse boot if `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` is set in
production) and the gateway launch-target-override escape hatch (honored only in
development/test). The dangerous failure is a **silent production → development
downgrade**, which disarms those guards.

The three sources, highest trust to lowest:

- **`ALFRED_ENVIRONMENT`** (os.environ) — highest trust; set by whoever controls process launch (systemd/compose).
- **`/etc/alfred/environment`** — middle trust; a root-owned system file.
- **`.env`** — lowest trust; a working-dir file writable by the app user.

**pydantic-settings reads only `os.environ` + `.env`; it never reads `/etc`.** Its
native order is `os.environ > .env`. So making `Settings` the independent authority
for `environment` yields the effective order `os.environ > .env > /etc` — a
lower-trust, app-writable `.env=development` would silently override a root-owned
`/etc=production`, disarming sec-002. Only `os.environ > /etc > .env` keeps `/etc`
above `.env`; under it `.env` can only fill a genuine gap and can never downgrade
a higher-trust source.

## Design — one canonical resolver, `Settings` delegates

### The single authority

`config/_environment_loader.py` grows the one and only precedence implementation:

```
resolve_environment()  # (renamed from / superseding load_environment)
  precedence: os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env
  returns EnvironmentLoadResult(value, source, conflict, conflicting_*_value, unrecognised_value)
```

- `.env` is parsed with **`python-dotenv`'s `dotenv_values(dotenv_path, interpolate=False)`** — the same parser pydantic-settings uses internally, so there is no second `.env` dialect. `interpolate=False` keeps it a pure key/value read.
- Grow `EnvironmentSource` with a **`DOTENV`** member. The existing conflict and
  UNRECOGNISED audit logic extends to cover the `.env` layer (e.g. a `.env`-only
  typo `staging` now echoes UNRECOGNISED for free).
- `.env` sits **lowest**: consulted only when `os.environ` **and** `/etc` are both
  absent. This closes the sec-002 downgrade *by construction*.

### `Settings` becomes one caller, not the owner (`config/settings.py`)

Two mechanisms, both required (belt-and-suspenders per the security review):

1. **Source exclusion.** Override `settings_customise_sources` to wrap the env and
   dotenv sources in a thin `_Without("environment")` adapter that pops the key, so
   pydantic can **never** populate `environment` from env/dotenv — only `init` or the
   resolver. (`Field(exclude=…)` is serialization-only and does NOT stop the env
   source under `env_prefix`; the source filter is the real exclusion.)

   ```python
   class _Without(PydanticBaseSettingsSource):
       def __init__(self, inner, *keys):
           self._inner, self._keys = inner, keys
           super().__init__(inner.settings_cls)
       def get_field_value(self, field, name):  # abstract; unused, __call__ overridden
           raise NotImplementedError
       def __call__(self):
           d = dict(self._inner())
           for k in self._keys:
               d.pop(k, None)
           return d

   @classmethod
   def settings_customise_sources(cls, settings_cls, init_settings, env_settings,
                                  dotenv_settings, file_secret_settings):
       return (init_settings,
               _Without(env_settings, "environment"),
               _Without(dotenv_settings, "environment"),
               file_secret_settings)
   ```

2. **Single `mode="wrap"` validator** (the only validator kind that can write a
   `PrivateAttr` on the *constructed* instance — the whole reason the ContextVar
   existed). It calls `resolve_environment()` exactly once when `environment` is
   absent, injects the value, and writes the `EnvironmentLoadResult` PrivateAttr:

   ```python
   @model_validator(mode="wrap")
   @classmethod
   def _resolve_environment(cls, data, handler):
       result = None
       if isinstance(data, dict) and "environment" not in data:
           result = resolve_environment()                       # the single read
           if result.value is not None:
               data = {**data, "environment": result.value}
       inst = handler(data)
       if result is not None and result.value == inst.environment:
           inst._environment_load_result = result
       return inst
   ```

**Deleted:** the `_ENVIRONMENT_LOAD_RESULT` ContextVar, the `_resolve_environment`
`mode="before"` validator, and the `_capture_environment_load_result` `mode="after"`
validator. Once-only holds (one call); "audited result matches validated field"
holds structurally (the same `result` sets both the injected value and the
PrivateAttr — no second read to disagree). `settings.environment_load_result` stays
the public property.

With source exclusion in place, `"environment" in data` means **explicitly
constructed** (`Settings(environment="test")`) — the sole legitimate bypass.

### The daemon gate (`cli/daemon/_commands.py`)

`_load_settings_or_die` keeps its pre-check (sec-001 audit-before-refuse; and it
avoids mis-attributing a placeholder-`deepseek_api_key` failure as
`environment_not_set`) but now calls the **same** `resolve_environment()`, then
constructs `Settings(environment=result.value)` explicitly — so the resolver runs
exactly once for the whole boot (the explicit `environment=` bypasses the
wrap-validator's read):

```python
result = resolve_environment()
if result.value is None:
    raise _EnvironmentNotSetError(result)   # sec-001 audited refusal; UNRECOGNISED echo; .env-aware
settings = Settings(environment=result.value)   # explicit ⇒ single read (bypasses the wrap-validator)
return settings, result                          # conflict audit (_commands.py:542) reads result.conflict
```

Because the daemon injects `environment` explicitly, the wrap-validator does **not**
re-read (single read per boot), and the daemon uses its **own** `result` for the
conflict audit — it does *not* rely on `settings.environment_load_result` (which the
wrap-validator only populates on a *self-resolving* `Settings()`).

**In-scope simplification (falls out of this rewrite):** with the ContextVar retired,
`settings.environment_load_result` is the authoritative property for every
self-resolved `Settings` (the bare `Settings()` at the CLI / gateway / alembic roots).
The daemon's `tuple[Settings, EnvironmentLoadResult | None]` return can then be slimmed
— either to a bare `-> Settings` by attaching `result` to the instance so the property
stays uniformly authoritative, or to a non-optional `tuple[Settings, EnvironmentLoadResult]`.
Either way there is exactly one `resolve_environment()` read per boot and one conflict
source; the exact return shape is a plan-level detail.

### Consumer rule (no re-divergence)

- **Core-process code reads `Settings.environment`** (via injected narrow config
  Protocols, per #351 — unchanged).
- **Only the three composition roots that cannot build `Settings`** call
  `resolve_environment()` directly: the daemon boot gate, `plugins/manifest_reader.py`
  (launcher subprocess), and `gateway/adapter_child_factory.py` (gateway container).

All four sites run identical precedence code, so no consumer re-implements
resolution. The implementation plan MUST verify (test) that `manifest_reader` and
`adapter_child_factory` behave correctly under the new `.env`-lowest layer — in the
deployed case `os.environ`/`/etc` are set so `.env` is inert; the risk is only that
a stray CWD `.env` supplies a value when nothing higher-trust does, which is safe
(lowest precedence, escalation-only).

## Multi-process rationale (why a shared primitive, not pure injection)

AlfredOS already uses dependency injection for config (#351: consumers depend on
narrow read-only Protocols; concrete `Settings` lives only at the composition root;
CLAUDE.md forbids global state — so no global singleton). But AlfredOS is
**multi-process**: the core daemon, the launcher subprocess, the gateway container,
and alembic are each their own composition root, and a Python `Settings` object
cannot cross a process boundary (the launcher subprocess gets a scrubbed
environment). Each process must resolve `environment` from **ambient sources** at
its own entry point. `resolve_environment()` is exactly that shared ambient-read
primitive — the fix makes every process agree on precedence. This design is fully
consistent with the #351 DI architecture, not a departure from it.

## Error handling / invariants preserved

- **sec-001** — the AuditWriter is built before `_load_settings_or_die`; an unset/
  unrecognised environment still emits an audited `DAEMON_BOOT_FAILED` row then exits 2.
- **`environment_source_conflict`** — flows from the single `EnvironmentLoadResult`
  (`result.conflict`), now covering the `.env` layer.
- **UNRECOGNISED echo (devex-222-01)** — preserved and now covers `.env`-only typos.
- **No silent failure** (CLAUDE.md hard rule 7) — every refusal is loud + audited.

## Testing

100%-style rigor on the resolver + the Settings validator; environment is
security-load-bearing, so the **full adversarial suite** runs.

Load-bearing tests:

1. **Downgrade oracle (security):** `os.environ` unset, `/etc/alfred/environment` =
   `production`, `.env` = `development`, `chdir(tmp)` → `Settings().environment ==
   "production"` **and** the sec-002 unsandboxed-in-production refusal still fires.
2. **Precedence / divergence oracle (core-eng):** `os.environ` unset, `/etc` =
   `development`, `.env` = `production`, `chdir(tmp)` → **both** `resolve_environment().value`
   **and** `Settings().environment` equal `development`. (Regresses the instant the
   source filter is dropped.)
3. **Positive Blocker-1 case:** `.env` = `production` only, `os.environ` cleared, no
   `/etc` → the daemon **boots** (`source == dotenv`).
4. **Container path stays green:** `.env` absent, `os.environ` set → success,
   `source == env_var`.
5. **`.env`-discovery hygiene:** every daemon-boot env test `monkeypatch.chdir(tmp_path)`
   (and clears `ALFRED_ENVIRONMENT`) so a dev's real repo-root `.env` never leaks a
   value and silently vacates an "unset" assertion.
6. **Vacuity guards:** each oracle isolates all three sources explicitly.
7. Existing `test_environment_loader.py` / `test_probe_environment_not_set.py` updated
   for the new source + the tuple→`Settings` collapse.

## Governance & adjacencies

- **ADR-0053 — three-layer environment precedence.** Owns: (1) canonical precedence
  `os.environ > /etc > .env`; (2) the single-resolver + `Settings`-delegates invariant
  (via `settings_customise_sources`), so no consumer re-implements precedence; (3)
  `.env` lowest — closes the sec-002 downgrade by construction; (4) retiring the
  ContextVar / dual-validator; (5) `EnvironmentSource.DOTENV`. Formally homes the
  previously un-homed **arch-002** decision and corrects the loader's stale
  "Spec §7.3" citation (PRD §7.3 is *Self-Healing*, not environment).
- **`.env.example`** — add `ALFRED_ENVIRONMENT` with the accepted triple + default +
  a comment (the missing-discoverability fix; absent today).
- **`python-dotenv`** — promote from transitive (via pydantic-settings/testcontainers,
  resolved at 1.2.2) to an **explicit direct dependency** in `pyproject.toml`, since
  the resolver now imports `dotenv_values` directly. Compatible (pydantic-settings
  requires `>=0.21.0`).
- **i18n** — the refusal message copy is unchanged (now true); no new `t()` key.
  `EnvironmentSource.DOTENV` surfaces only in audit-row/structlog values, which are
  not `t()` scope.

## Scope

**IN (this PR):** the single resolver + `Settings` delegation, ADR-0053, the stale
§7.3 citation fix, `.env.example` entry, the `python-dotenv` direct dep, the daemon
factory's `tuple → Settings` collapse, and the tests above.

**OUT (separate follow-up issue, with its own ADR-0054 — a #351 continuation):**
standardize `gateway` (`cli/gateway/_commands.py:150`) and `alembic`
(`memory/migrations/env.py:40`) onto the friendly-error factory; fix the supervisor
re-construction smell (`cli/supervisor.py:697,956` re-read the whole environment to
grab one interval → should receive injected `settings`/a narrow Protocol). This is all
real #351 DIP debt — none environment-related, none correctness/security bugs.

**Scope boundary rule:** a change about *how `environment` is resolved* is in; a
change about *how the `Settings` object is constructed/injected generally* is out.

## Risks / residuals

- **Two `.env` parsers.** The resolver uses `dotenv_values`; pydantic parses the same
  `.env` for other fields. Excluding `environment` from pydantic's sources means only
  the resolver's parser touches `environment`, and both are `python-dotenv` — but the
  plan pins `dotenv_values(interpolate=False)` to keep semantics identical.
- **CWD-relative `.env`.** `.env` is resolved relative to CWD (matching pydantic). A
  CWD-planted `.env` is low-severity (lowest precedence, escalation-only), but the
  plan matches pydantic's `env_file` resolution rather than inventing a new anchor.
- **`manifest_reader` / `adapter_child_factory` blast radius.** Newly `.env`-aware via
  the shared resolver; the plan adds a behavior test at each site (see Consumer rule).

## References

- Epic #469; #340 PR2b-golive (compose-forward fix); arch-002 (#174 dual-source loader);
  #351 config-as-interface / DIP (`docs/python-conventions.md:176`).
- Fleet convergence: alfred-architect, alfred-security-engineer, alfred-core-engineer,
  alfred-devex-reviewer (all endorse; core-engineer reversed an initial "defer to
  Settings" position after the trust-precedence + call-site analysis).
