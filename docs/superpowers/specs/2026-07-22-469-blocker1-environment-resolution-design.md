# #469 Blocker 1 — one canonical environment-resolution path

**Status:** design v2 — revised after a 10-lane `/review-plan` fleet + coordinator
cross-check round (0 Critical, 13 High, 27 Medium, 12 Low; 8/8 solo findings
confirmed, 0 retracted, 0 disputed). Branch `469-blocker1-environment-resolution`.
Parent epic: #469 (first-run experience). This spec covers **Blocker 1 only**.

Four design decisions were settled with the human during review and are marked
**[D1]–[D3]/[Db]** below.

## Problem

`alfred daemon start` refuses to boot with:

> Settings.environment is not set. Refusing to boot … Set ALFRED_ENVIRONMENT to
> one of: development, production, test (**in your .env**) …

…even when the operator set `ALFRED_ENVIRONMENT` in `.env` exactly as instructed.
They do the named remedy, re-run, and hit the identical refusal — unrecoverable
without reading source.

## Root cause (reproduced)

The boot gate `_load_settings_or_die()` (`cli/daemon/_commands.py:346`) calls the
standalone `load_environment()` (`config/_environment_loader.py`), which reads
**only** `os.environ["ALFRED_ENVIRONMENT"]` and `/etc/alfred/environment`, and
refuses **before** `Settings()` is constructed. But `Settings` (pydantic-settings,
`env_file=".env"`) **does** read `.env`. Verified: with `ALFRED_ENVIRONMENT=production`
in a `.env` file and absent from `os.environ`, `load_environment()` returns
`value=None` (→ refusal) while `Settings()` in the same run resolves
`environment='production'` from `.env`. The pre-Settings gate is a less-capable,
`.env`-blind duplicate. Masked in compose (compose forwards `.env`→`os.environ`);
broken on the documented host path and any `.env`-only setup.

## The trust-precedence constraint

`environment` is **security-load-bearing**: `environment == "production"` gates the
sec-002 unsandboxed-in-production refusal (`_commands.py:562`) and (permissively)
the gateway launch-target-override escape hatch. The dangerous failure is a **silent
production → development downgrade**. The three sources, highest trust to lowest:

- **`ALFRED_ENVIRONMENT`** (os.environ) — set by whoever controls process launch.
- **`/etc/alfred/environment`** — a root-owned system file.
- **`.env`** — a working-dir file writable by the app user.

pydantic-settings reads only `os.environ` + `.env`; it **never** reads `/etc`. Its
native order is `os.environ > .env`, so letting `Settings` be the independent
authority yields `os.environ > .env > /etc` — an app-writable `.env=development`
could override a root-owned `/etc=production`. Only `os.environ > /etc > .env` keeps
`/etc` above `.env`.

## Design — one canonical resolver, `Settings` delegates

### The single authority (`config/_environment_loader.py`)

`resolve_environment()` becomes the one and only precedence implementation:
**`os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env`**, returning an
`EnvironmentLoadResult(value, source, conflict, conflicting_*_value, unrecognised_value)`.

- `.env` is parsed with **`python-dotenv`'s `dotenv_values(dotenv_path, interpolate=False)`**.
  `interpolate=False` is chosen to **eliminate a `$VAR` injection vector**, NOT
  because it matches pydantic (pydantic defaults `interpolate=True` — the "identical
  parser semantics" claim from v1 was wrong; the difference is immaterial for a
  Literal-triple `environment` value and is called out in ADR-0053).
- Grow `EnvironmentSource` with **`DOTENV`**. The `.env` value is `.strip()`-normalized
  identically to the other two sources (whitespace/quoted-value symmetry).
- **[D3] Short-circuit on a typo'd higher source.** The precedence is resolved
  top-down: the **highest source that is SET** decides. If that source's value is
  **not** in the Literal triple, the resolver returns `UNRECOGNISED` (echoing the
  typo) and does **not** silently fall through to a valid lower source. This prevents
  a downgrade-via-typo (root typos `/etc`, a `.env=development` cannot silently win).
  This is a deliberate behavior change from today's fall-through; it is specified and
  tested. A source that is **unset** (absent/empty) is skipped, not a short-circuit.
- **`.env` read-failure posture (Theme B/err-01).** `dotenv_values` **raises**
  `PermissionError` on a present-but-unreadable `.env` (routine now #470 locks `.env`
  to 0600). The resolver catches `PermissionError`/`OSError`/`IsADirectoryError`/
  `FileNotFoundError` on the `.env` read and treats them as **absent** — mirroring the
  existing `/etc` guard — so a mode-misconfigured `.env` never crashes boot with a raw,
  un-audited traceback (CLAUDE.md hard rule 7). Applied at **all** `.env`-reading
  sites (see Consumer rule).
- **Residual (err-03):** `dotenv_values` *silently* drops a malformed line (unbalanced
  quote / missing `=`). If the `ALFRED_ENVIRONMENT` line itself is malformed it reads
  as absent → an `environment_not_set` refusal in a parse-error guise. Documented as a
  known limitation with a test pinning the behavior; a friendlier message is a
  follow-up (we do not re-introduce a hand parser to detect it).
- `.env` **can never participate in a two-source `conflict`** (it is the lowest,
  gap-fill-only layer) — only the `UNRECOGNISED` branch extends to it. This negative
  invariant is pinned by test so no phantom `.env`-conflict field/branch is written.

### `Settings` becomes one caller (`config/settings.py`)

1. **Source exclusion.** `settings_customise_sources` wraps the env + dotenv sources
   (and, for a security-load-bearing field, `file_secret_settings`) in a **hardened
   `_Without`** adapter that pops the field key, so pydantic never populates
   `environment` from any of its own sources. Hardening required (core-eng-01/sec-p5):
   - **Derive the popped key from the field's alias set**, not the hardcoded string
     `"environment"` — if `environment` ever gains a `validation_alias`, a literal pop
     silently rots and reopens the downgrade with no failing test.
   - **Forward pydantic-settings' per-source state protocol** (`_set_current_state` /
     `_set_settings_sources_data`) to the wrapped inner source, and give each wrapper a
     **distinct identity** so the two wrappers do not collide under the same type-name
     in pydantic's per-source states dict (an undocumented 2.14.2 internal — **pin the
     pydantic-settings version** and add a regression test).
   - A test asserts pydantic **cannot** populate `environment` from `.env` (the
     exclusion is airtight), so a future source-ordering edit fails loudly.
2. **Single `mode="wrap"` validator** replaces the before+after validator pair and the
   `_ENVIRONMENT_LOAD_RESULT` ContextVar (both **deleted**). It calls
   `resolve_environment()` exactly once when `environment` is absent, injects the value,
   and writes the `EnvironmentLoadResult` PrivateAttr on the constructed instance
   (verified valid in 2.14.2: `Settings` is not frozen; `init_settings` outranks the
   validator). `settings.environment_load_result` stays the public property, populated
   on any *self-resolving* `Settings()`.

With exclusion in place, `"environment" in data` means **explicitly constructed**
(`Settings(environment="test")`) — the sole legitimate bypass. Direct-invocation unit
tests of the old `before`-validator (`test_settings_environment_mandatory.py`) are
updated for the `wrap` signature.

### [D1] Trust-floor at the escape-hatch gate — resolver stays uniform

The resolver is **uniformly `.env`-aware at every call site** (the clean single-path
directive). The escape-hatch danger (dev/test is the *permissive* state, so a CWD
`.env=development` could flip a fail-closed refusal to fail-open) is closed **at the
consumer, by construction**: `gateway/adapter_child_factory._resolve_launch_target`
honors dev-mode **only when `result.source in {ENV_VAR, ETC_FILE}`** — never `DOTENV`.
So a lowest-trust `.env` can never unlock the override. The plan audits each
subprocess consumer (`manifest_reader`, `adapter_child_factory`) for a
permissive-in-dev behavior and applies the trust-floor where one exists. Production
was already safe (the override map is `None` in prod, so `environment` isn't read
there); the trust-floor makes dev/test safe too and de-risks the adversarial test.

### The daemon gate (`cli/daemon/_commands.py`)

Resolve once, then construct explicitly (single read/boot):

```python
result = resolve_environment()
if result.value is None:
    raise _EnvironmentNotSetError(result)   # sec-001 audited refusal; UNRECOGNISED echo; .env-aware
settings = _build_settings_or_die(environment=result.value)  # [Db]: distinct audited failure below
return settings, result                      # NON-OPTIONAL tuple; conflict audit reads result.conflict
```

- **[Db] Distinct audited reason for a post-env `Settings()` failure.** The v1 sketch
  dropped the defensive `except SettingsError` arm (err-02/reviewer-02: a placeholder
  `deepseek_api_key` would escape as a raw, un-audited traceback). Instead of
  *re-labeling* that as `environment_not_set`, we mint a **new** daemon boot-failure
  reason (`SettingsInvalidFailure` / `settings_invalid`) with its own audited row + its
  own `t()` message surfacing the pydantic detail. sec-001 audit-before-refuse holds;
  the failure is correctly labeled.
- **Return shape (arch-003/sec-p2/reviewer-06):** keep the **non-optional
  `tuple[Settings, EnvironmentLoadResult]`**. Do NOT "attach `result` to the instance"
  (that re-opens the real arch-002 *no-PrivateAttr-smuggling* decision, and leaves the
  conflict audit reading `None` on the daemon's explicit-construction path). The
  conflict audit at `_commands.py:542` reads the daemon's own `result`.

### Consumer rule

Core-process code reads `Settings.environment` (injected narrow Protocols, #351 —
unchanged). Only the three composition roots that cannot build `Settings` call
`resolve_environment()` directly: the daemon boot gate, `plugins/manifest_reader.py`,
`gateway/adapter_child_factory.py`. All run identical precedence code; the `.env`
read-error guard is inside `resolve_environment()`, so all three inherit it.

## Multi-process rationale

AlfredOS already uses DI for config (#351: narrow read-only Protocols; concrete
`Settings` only at the composition root; CLAUDE.md forbids global state). But it is
**multi-process** — the daemon, the launcher subprocess, the gateway container, and
alembic are each their own composition root, and a `Settings` object cannot cross a
process boundary. Each process resolves `environment` from ambient sources at its own
entry point; `resolve_environment()` is that shared primitive. Consistent with #351,
not a departure.

## The `ALFRED_ENV` divergence (arch-002 / sec, confirmed)

A **fifth** security-load-bearing site, `security/…/content_store_base.py:149`, reads a
**different** variable `ALFRED_ENV` (a free-form capability-gate selector, `test`→RealGate)
to drive the sec-S3-003 production-refusal. ADR-0053's "single resolver" invariant is
therefore scoped to **`ALFRED_ENVIRONMENT`**, and the ADR **names `ALFRED_ENV` as a known,
intentional divergence** (different semantics, different refusal). Security also found a
**latent gap** — an `/etc`-set `ALFRED_ENVIRONMENT=production` with `ALFRED_ENV` unset does
**not** trip sec-S3-003. Unifying/reconciling the two variables is **out of scope** here
(they are semantically distinct) and filed as a follow-up; this PR only documents the
divergence honestly so the invariant is not overclaimed.

## Error handling / invariants preserved

- **sec-001** — AuditWriter built before the gate; unset/unrecognised environment and a
  post-env `Settings()` failure both emit an audited `DAEMON_BOOT_FAILED` row then exit 2.
- **`environment_source_conflict`** — from the single `EnvironmentLoadResult`
  (`result.conflict`); `.env` never participates.
- **UNRECOGNISED echo (devex-222-01)** — preserved; now covers `.env`-only typos.
- **No silent failure** (hard rule 7) — the `.env` read-error guard converts a
  `PermissionError` into an audited refusal, not a raw crash.

## Testing

Full **adversarial suite** runs (environment is security-load-bearing). Load-bearing tests:

1. **Downgrade oracle:** os.environ unset, `/etc`=`production`, `.env`=`development`,
   `chdir(tmp)` → `Settings().environment == "production"` **and** sec-002 fires.
2. **Divergence oracle:** same-input → `resolve_environment()` **and** `Settings().environment`
   agree; assert `.value` **and** `.source` (asserting `.value` alone greens vacuously on a
   leaked `ALFRED_ENVIRONMENT`).
3. **[D3] Typo short-circuit:** os.environ=`staging` (invalid) + `.env`=`production` (valid)
   → `UNRECOGNISED` refusal echoing `staging`, NOT `production`.
4. **`.env` read-error:** a present-but-unreadable `.env` (0600, wrong owner / chmod 000) →
   treated as absent + audited, never a raw traceback. At all three `.env`-reading sites.
5. **Escape-hatch hermeticity (Theme A):** chdir-isolate the **release-blocking**
   `tests/adversarial/comms/test_launch_target_override_refusal.py` (add `.env` isolation to
   its unset/staging/unknown cases); add a **positive gateway downgrade oracle**
   (`/etc`=production + `.env`=development + override injected → still refused, because
   source≠DOTENV) and a `manifest_reader` os.environ-beats-`.env` precedence test.
6. **Exclusion airtight:** pydantic cannot populate `environment` from `.env` (guards the
   `_Without`/alias regression); `.env`-only UNRECOGNISED + whitespace-symmetry cases.
7. **Positive Blocker-1:** `.env`=`production` only, os.environ cleared, no `/etc` → **boots**
   (`source == dotenv`). **Container path:** `.env` absent, os.environ set → success
   (`source == env_var`).
8. **`.env`-discovery hygiene:** every daemon-boot env test `monkeypatch.chdir(tmp_path)` +
   clears `ALFRED_ENVIRONMENT`, so a dev's real repo-root `.env` never leaks a value.
9. Update `test_environment_loader.py`, `test_probe_environment_not_set.py`,
   `test_settings_environment_mandatory.py` (before→wrap), `test_settings.py`; wire the
   `config/observability`-style coverage target to a **real per-module gate** (not a paper
   gate, cf. #474).

## Governance & adjacencies

- **ADR-0053 — three-layer environment precedence.** Owns: (1) canonical
  `os.environ > /etc > .env`; (2) the single-resolver + `Settings`-delegates invariant
  **scoped to `ALFRED_ENVIRONMENT`**, naming `ALFRED_ENV` as a known divergence; (3) `.env`
  lowest closes the sec-002 downgrade by construction + the trust-floor closes the
  escape-hatch; (4) retiring the ContextVar/dual-validator; (5) `EnvironmentSource.DOTENV` +
  the short-circuit semantics. It **homes the precedence decision (no prior ADR does)** —
  the v1 "homes arch-002" label was a **mis-attribution** (arch-002 was the tuple/
  no-smuggling finding) and is dropped. Corrects the loader's stale "Spec §7.3" citation
  (PRD §7.3 is Self-Healing; §7.1 is the candidate anchor). **ADR-0054 is not pre-reserved**
  (repo already has a duplicate 0047; author it when the follow-up is scheduled).
- **Doc drift (Theme E)** — update, IN scope: `docs/subsystems/supervisor.md:373-378` (old
  two-source model), `docs/glossary.md:1645` (CLAUDE.md's single vocabulary source — stale
  symbol + no precedence entry), the loader's whole module docstring ("Dual-source"),
  `plugins/manifest_reader.py:40` + `docs/adr/0039` dangling `:func:` refs.
- **[D2] `.env.example`** — add `ALFRED_ENVIRONMENT=production` **uncommented** (closes the
  host loop via bare `cp`, keeps compose at production — no silent downgrade, since
  `bin/alfred-setup.sh` auto-`cp`s it and compose promotes `.env`→`os.environ`), with a
  comment naming the accepted triple and **disambiguating from the pre-existing `ALFRED_ENV`**
  capability-gate key. Add a test that `.env.example`'s value cannot downgrade the compose
  default.
- **`python-dotenv`** — promote transitive→explicit **direct dep** in `pyproject.toml`,
  floored at `>=1.2.2` (resolved; ADR-0044 flooring convention), `uv lock` (no change
  expected); justify the (already-present) fourth-party in the PR description.
- **i18n** — the existing refusal copy is now accurate; the new `settings_invalid` reason
  needs **one new `t()` key**. The `_commands.py` rewrite line-shifts the refusal `t()` calls,
  so run the **pybabel extract/update/compile** cycle (`-D alfred`) and commit the `#:` ref
  churn. `EnvironmentSource.DOTENV` is audit/structlog-only (not `t()` scope).

## Scope

**IN (this PR):** the single resolver + `Settings` delegation, the trust-floor, the
short-circuit semantics, the `.env` read-error guard, the distinct `settings_invalid`
reason, ADR-0053, the doc-drift updates, the `.env.example` entry, the `python-dotenv`
direct dep, the daemon factory's non-optional-tuple return, and the tests above.

**OUT (follow-up issues):** the settings-factory DIP consolidation (its own ADR-0054);
reconciling `ALFRED_ENV`/`ALFRED_ENVIRONMENT` + the sec-S3-003 latent gap; a friendlier
malformed-`.env`-line message. The CI first-run smoke lane belongs to the epic.

**Boundary rule:** a change about *how `environment` is resolved* is in; a change about
*how the `Settings` object is constructed/injected generally*, or about the separate
`ALFRED_ENV` variable, is out.

## Risks / residuals

- **Two `.env` parsers** — the resolver's `dotenv_values` vs pydantic's parse of the same
  file for other fields; excluding `environment` from pydantic's sources means only the
  resolver touches `environment`, and `interpolate=False` removes the interpolation vector
  (residual is a benign parser difference, not a divergence).
- **Malformed `.env` line** silently dropped by `dotenv_values` (err-03) — documented + tested.
- **`_Without` internal-API dependency** on pydantic-settings 2.14.2's per-source state
  protocol — mitigated by forwarding it, pinning the version, and a regression test.
- **CWD-relative `.env`** — matches pydantic's `env_file` resolution; a CWD-planted `.env` is
  lowest-precedence + gated out of the escape hatch by the trust-floor.

## References

- Epic #469; #340 PR2b-golive; arch-002 (#174 dual-source loader); #351 config-DIP
  (`docs/python-conventions.md:176`).
- Review: 10-lane `/review-plan` fleet + `alfred-review-coordinator` (0 Crit / 13 High /
  27 Med / 12 Low; 8/8 solos confirmed). Decisions D1–D3 + Db settled with the human.
