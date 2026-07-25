# #499 — Gateway `Settings()` decoupling (roadmap #469 Step 2)

- **Issue:** [#499](https://github.com/alfred-os/AlfredOS/issues/499) — gateway can't
  construct `Settings()`: decouple adapter-list resolution from a full `Settings()` (ADR-0036).
- **Epic:** [#469](https://github.com/alfred-os/AlfredOS/issues/469) first-run experience ·
  **Roadmap:** `docs/superpowers/specs/2026-07-24-469-first-run-path-to-green-roadmap.md` (Step 2).
- **Diagnosed by:** the #494 e2e first-run boot lane — the `alfred-gateway` strict-xfail
  (`tests/e2e/test_first_run_boot.py::test_gateway_is_healthy`).
- **Owners:** alfred-gateway / alfred-core engineers + the full security lane (a trust-boundary
  decoupling).

## Problem

`alfred.cli.gateway._commands._resolve_hosted_adapter_ids()` (`src/alfred/cli/gateway/_commands.py:143`)
constructs a full `Settings()` purely to read `settings.comms_enabled_adapters`:

```python
settings = Settings()                       # requires deepseek_api_key + environment
resolved = (_resolve_adapter_kind(a) for a in settings.comms_enabled_adapters)
return [kind for kind in resolved if kind != _TUI_DIAL_IN_ADAPTER_ID]
```

`Settings.deepseek_api_key: SecretStr` is a required, no-default field (`settings.py:160`). The
`alfred-gateway` compose service is deliberately **denied** provider secrets (ADR-0036 — no vault
key on the gateway): its env block sets `ALFRED_DEEPSEEK_BASE_URL` but **no**
`ALFRED_DEEPSEEK_API_KEY`. So `Settings()` raises, `_commands.py`'s boot maps it to
`SettingsError → _EXIT_CONFIG_FAILED` (`_commands.py:294–297`), and the gateway never reaches
`healthy`.

The provider key is the **sole** missing field on the gateway path: the compose service *does*
set `ALFRED_ENVIRONMENT: production` (`docker-compose.yaml`, `alfred-gateway.environment`), so the
`environment` required field resolves; every other `Settings` field has a default. The failure is
narrowly the provider-key requirement, independent of the opt-in-Discord default
(`ALFRED_GATEWAY_HOSTED_ADAPTERS` → `ALFRED_COMMS_ENABLED_ADAPTERS`, default `[]`).

### Why this is the gate for the ratchet

`test_gateway_is_healthy` brings up `alfred-gateway` alone (`up -d --no-deps`) and asserts the
Docker healthcheck reaches `HEALTHY`. It is `xfail(strict=True)` naming exactly this blocker. When
the decoupling lands, the test **XPASSES**, and `strict=True` reds the lane — the tripwire that
forces the assertion to tighten. This PR turns that red into an un-xfailed green (see *The ratchet*).

## Security constraint (must-preserve)

The `comms_enabled_adapters` field validator `Settings._validate_comms_enabled_adapters`
(`settings.py:449`) is a genuine trust boundary. It rejects any adapter id that is mis-charset,
is the single-segment `.`/`..` traversal probe, resolves outside `plugins/`, or names no real
`plugins/<id>/manifest.toml`.

On the gateway path this validation is **load-bearing**: `_resolve_adapter_kind()`
(`_commands.py:135`) computes `repo_root() / "plugins" / plugin_package_id / "manifest.toml"` and
calls `.read_text()` with **no sink-local containment re-check** — unlike
`security/capability_gate/_comms_adapter_grants.py`, which re-checks `plugins/` containment at its
read sink (its "Sink-local containment (DiD, #364)" block). `security/_config_protocols.py:21`
records the invariant explicitly: *"`Settings.comms_enabled_adapters` is validated by
`_validate_comms_enabled_adapters` — every id is [path-safe]."*

Therefore the decoupled path **must run the same validation**. A hand-rolled parser that skips it
would open an operator-controlled path traversal on the gateway
(`ALFRED_GATEWAY_HOSTED_ADAPTERS=["../../etc/…"]` → arbitrary `read_text()`).

## Chosen approach — minimal `BaseSettings` subclass + shared validator

Extract the security-critical validation body from `Settings._validate_comms_enabled_adapters`
into a module-level pure function in `settings.py`, and add a tiny second settings model that the
gateway constructs instead of full `Settings()`.

```python
# settings.py — one definition of the security-critical rule.
def validate_comms_adapter_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    """Reject any adapter id that is mis-charset, traversal-shaped, or has no real manifest.

    THE single source of truth for comms-adapter-id path-safety. Both Settings (full core
    config) and GatewayHostedAdaptersSettings (the gateway's key-free read) validate through
    it, so the two can never drift (CLAUDE.md hard rule #7; security/_config_protocols.py:21).
    """
    # (moved verbatim from _validate_comms_enabled_adapters: charset, {".", ".."},
    #  plugins/-containment, manifest-is-file)
    ...
    return value


class Settings(BaseSettings):
    ...
    @field_validator("comms_enabled_adapters")
    @classmethod
    def _validate_comms_enabled_adapters(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return validate_comms_adapter_ids(value)


class GatewayHostedAdaptersSettings(BaseSettings):
    """The gateway's key-free read of the hosted-adapter allowlist (ADR-0036, #499).

    ONE field. The gateway holds no provider secret, so it MUST NOT construct the full
    Settings (whose deepseek_api_key is required-no-default). pydantic-settings does the
    ALFRED_COMMS_ENABLED_ADAPTERS env-read + JSON-decode natively; the shared validator
    keeps the path-safety identical to the full Settings.
    """

    model_config = SettingsConfigDict(
        env_prefix="ALFRED_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )
    comms_enabled_adapters: tuple[str, ...] = Field(default=())

    @field_validator("comms_enabled_adapters")
    @classmethod
    def _validate(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return validate_comms_adapter_ids(value)
```

```python
# cli/gateway/_commands.py — construct the minimal model, no provider key.
def _resolve_hosted_adapter_ids() -> list[str]:
    from alfred.config.settings import GatewayHostedAdaptersSettings

    settings = GatewayHostedAdaptersSettings()
    resolved = (_resolve_adapter_kind(a) for a in settings.comms_enabled_adapters)
    return [kind for kind in resolved if kind != _TUI_DIAL_IN_ADAPTER_ID]
```

### Why this over the alternatives

- **② hand-rolled env read** (`os.environ` → `json.loads` → tuple → validate): re-implements
  pydantic-settings' JSON env-decode (unset vs `""` vs whitespace, JSON edge cases) — the exact
  "hand-rolled config re-parser" drift trap flagged in project memory (#269). Rejected.
- **③ make `deepseek_api_key` optional / gateway flag**: weakens the core's required-key
  invariant and risks a key path on the gateway. Rejected by the issue and ADR-0036.

### Boundaries / decisions

- **`GatewayHostedAdaptersSettings.__init__` error handling.** The minimal model does **not**
  need to *inherit* from `Settings` (it shares no fields with it), but it **must replicate**
  `Settings`' construction-failure behaviour: its own `__init__` lifts every construction fault
  (a validator `ValueError` on a malformed id, a pydantic `ValidationError`, a malformed-JSON
  decode) to `SettingsError` via `raise SettingsError(str(exc)) from exc`, exactly as
  `Settings.__init__` does. That is required because `start_gateway` catches only `SettingsError`
  in its config arm (`_commands.py:287–297`), so an un-lifted construction fault would escape as a
  raw traceback instead of the existing config refusal. **Shipped note:** each model carries its
  OWN on-class `__init__` (not a shared base) — the pydantic mypy plugin only honours a user
  `__init__` defined directly on the model class; see the plan's *Shipped implementation
  refinements*. The security-critical single-source-of-truth is the shared
  `validate_comms_adapter_ids` validator, not the (deliberately duplicated) 3-line lift.
- **No `bin/alfred-setup.sh` change.** The roadmap's "consider `--no-deps`" is unnecessary: a
  *healthy* gateway satisfies the `service_healthy` dependency, so `docker compose run alfred-core
  migrate` stops *hanging*. It then fails on blocker B (#500), whose fix is Step 3's corner-turn —
  `test_setup_sh_completes` stays xfail on #501/#500. Single-responsibility PR.
- **Non-empty (Discord) path preserved, not the deliverable.** Full validation + `_resolve_adapter_kind`
  still work for `["alfred_discord"]`, but end-to-end success in the *shipped* image depends on
  #500 (the shared `docker/alfred-core.Dockerfile` shipping `plugins/` + correct `_REPO_ROOT`).
  The e2e default is `[]`, which touches no manifest. Out of scope.

## The ratchet (test changes)

`tests/e2e/test_first_run_boot.py`:

- Remove the `@pytest.mark.xfail(strict=True)` on `test_gateway_is_healthy`.
- Restore its health poll to the full budget: drop `timeout_s=_XFAIL_HEALTH_TIMEOUT_S` so it uses
  the default 180s (per the in-code note "Restore the full budget when Step 2/3 un-xfails them").

`tests/e2e/_services.py`:

- Remove `"alfred-gateway"` from `XFAIL_SERVICES`.
- `test_every_compose_service_is_classified` requires every compose service ∈
  `BASELINE_SERVICES ∪ XFAIL_SERVICES`. `BASELINE_SERVICES` is specifically the *pulled-image
  infra tier* co-booted in the `boot_stack` fixture (`up -d --no-deps *_BASELINE`); the gateway
  needs a build and has its own dedicated test, so it does **not** belong there. Add a third
  bucket and widen the classification union:

  ```python
  # Services graduated from XFAIL to "asserted healthy by a dedicated build-required test"
  # (not the pulled-image infra baseline the fixture co-boots). Grows as blockers land.
  HEALTHY_APP_SERVICES: frozenset[str] = frozenset({"alfred-gateway"})
  ```

  ```python
  known = _services.BASELINE_SERVICES | _services.HEALTHY_APP_SERVICES | set(_services.XFAIL_SERVICES)
  ```

  This keeps the ratchet honest: services migrate `XFAIL → HEALTHY_APP` as blockers land; at
  Step 5, `XFAIL_SERVICES` empties and everything is baseline-or-app-healthy.

`tests/unit/cli/gateway/` (per-PR gated — the e2e lane is nightly-only):

- Extend `test_resolve_hosted_adapter_ids_empty_env.py`: prove the decoupled path resolves `[]`
  with **no** `ALFRED_DEEPSEEK_API_KEY` and **no** `ALFRED_ENVIRONMENT` in env (the exact
  key-free gateway posture — the current test sets both because the old code needed them).
- Add a **security regression-lock**: a traversal-shaped `ALFRED_COMMS_ENABLED_ADAPTERS` entry is
  rejected by the decoupled path (construction raises), so decoupling did not drop the guard.
- Add a positive resolve: a real adapter id (`alfred_discord`) resolves to its canonical kind
  (`discord`) through the decoupled path (reusing the existing reconciliation fixtures).
- Add a shared-validator identity test: `GatewayHostedAdaptersSettings` and `Settings` reject the
  same bad id set (they call one function) — mutation-resistant, not tautological.

## Verification checkpoint (de-risk)

Before claiming done, run a real local `docker compose up -d --no-deps alfred-gateway` +
`alfred gateway healthcheck` (or Docker health) and confirm the gateway reaches `healthy`
standalone — core absent → healthy-while-buffering per the healthcheck contract
(`_commands.py:564–573`: a core-down buffering gateway is HEALTHY; only wedged-past-breaker is
unhealthy). If the gateway needs Redis to reach healthy, that is a NEW finding the harness's
diagnosis did not name — handle it then via systematic-debugging, do not pre-solve.

## Files touched

| File | Change |
| --- | --- |
| `src/alfred/config/settings.py` | Extract `validate_comms_adapter_ids()`; add `GatewayHostedAdaptersSettings`; `_validate_comms_enabled_adapters` delegates to the shared fn. |
| `src/alfred/cli/gateway/_commands.py` | `_resolve_hosted_adapter_ids()` constructs `GatewayHostedAdaptersSettings` instead of `Settings`; update its docstring. |
| `tests/e2e/test_first_run_boot.py` | Un-xfail `test_gateway_is_healthy`; restore full health budget. |
| `tests/e2e/_services.py` | Remove gateway from `XFAIL_SERVICES`; add `HEALTHY_APP_SERVICES`; widen classification union. |
| `tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py` (+ new/sibling unit tests) | Key-free empty resolve; traversal regression-lock; positive resolve; shared-validator identity. |

## Out of scope

- Blocker B (#500) core Dockerfile / `_REPO_ROOT`; the Discord-on-gateway end-to-end path.
- `bin/alfred-setup.sh` (`--no-deps`); `test_setup_sh_completes` (stays xfail on #501/#500).
- Promoting the e2e lane to release-blocking (Step 5).

## Success criteria

1. `alfred-gateway` reaches Docker `healthy` with no provider key (verified locally + via the
   un-xfailed nightly `test_gateway_is_healthy`).
2. The path-traversal guard on the gateway adapter-id path is provably intact (regression-lock).
3. One definition of the adapter-id validator; `Settings` and `GatewayHostedAdaptersSettings`
   share it.
4. `make check` green (mypy strict + pyright + ruff + unit); security lane clean; the full
   adversarial suite passes (a security-boundary touch).
