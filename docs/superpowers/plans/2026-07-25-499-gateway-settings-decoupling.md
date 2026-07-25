# Gateway `Settings()` Decoupling (#499) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the gateway resolve its hosted-adapter allowlist without a provider key by constructing a minimal `GatewayHostedAdaptersSettings` (sharing the security-critical adapter-id validator) instead of a full `Settings()`, and flip the #494 e2e gateway xfail to a green assertion.

**Architecture:** Extract the security-critical adapter-id validation body from `Settings._validate_comms_enabled_adapters` into a module-level pure function `validate_comms_adapter_ids()`. Add a one-field `GatewayHostedAdaptersSettings(BaseSettings)` whose validator delegates to that function; both it and `Settings` lift construction failures to `SettingsError` via a shared base. `_resolve_hosted_adapter_ids()` constructs the minimal model. pydantic-settings does the `ALFRED_COMMS_ENABLED_ADAPTERS` env-read + JSON-decode natively; the shared validator keeps path-safety identical across both models (ADR-0036: the gateway holds no provider secret).

**Tech Stack:** Python 3.14+, pydantic-settings v2, pytest, docker compose (e2e nightly lane).

**Spec:** `docs/superpowers/specs/2026-07-25-499-gateway-settings-decoupling-design.md`
**Plan review:** the 6-reviewer `/review-plan` fleet (2026-07-25) — findings folded into this revision (High test-001/rev-001, the mypy type-ignore, the containment-branch coverage gap, the missing key-free positive resolve, the sed breadth, + the test/doc polish set).

## Global Constraints

Every task's requirements implicitly include these (verbatim from the spec + CLAUDE.md):

- **Python 3.14+ idioms.** PEP 604 unions / PEP 585 built-in generics. Never `Optional[X]` / `typing.List`. No `Any` without justification.
- **`mypy --strict` + `pyright` clean; `ruff check` + `ruff format --check` clean.** The minimal model's inherited untyped `__init__` means every `GatewayHostedAdaptersSettings()` call site carries `# type: ignore[no-untyped-call]` (same as the existing `Settings()` at `_commands.py:157`).
- **Security HARD — the adapter-id validator is a trust boundary.** The decoupled gateway path MUST run the *identical* validation (charset, `.`/`..` rejection, `plugins/`-containment, manifest-exists). Never bypass it. The `_resolve_adapter_kind` read sink in `_commands.py` has NO sink-local re-check, so the construction-time validator is the sole path-traversal guard there — its `is_relative_to` containment branch MUST be directly tested.
- **No silent failures in the config path.** `GatewayHostedAdaptersSettings` construction faults (bad id AND malformed JSON) MUST lift to `alfred.config.settings.SettingsError` so `start_gateway`'s config arm (`_commands.py:294`) catches them — never a raw `ValidationError` traceback.
- **ADR-0036 — the gateway holds no provider secret.** Do NOT give the gateway the key; do NOT make `deepseek_api_key` optional on `Settings`.
- **Single source of truth.** Exactly one definition of the adapter-id validation logic; both models delegate to it.
- **i18n.** No new hardcoded operator-facing strings. The validator messages stay raw English (existing convention — Settings loads before `t()`). No `t()` catalog changes in this PR.
- **Conventional Commits** with a literal `#499` AFTER the colon in EVERY commit subject. Each commit ends with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer + the `Claude-Session:` trailer. **The repo is REBASE-ONLY** (squash + merge-commit disabled).
- **`make check` before every push.** Run the FULL adversarial suite (`uv run pytest tests/adversarial`) — this change is security-adjacent (touches the trust-boundary validator).

## File Structure

| File | Responsibility |
| --- | --- |
| `src/alfred/config/settings.py` | Add `_SettingsErrorLifting` base (holds the `__init__` lift); add module-level `validate_comms_adapter_ids()`; make `Settings` inherit the base; `_validate_comms_enabled_adapters` delegates; add `GatewayHostedAdaptersSettings`. |
| `src/alfred/cli/gateway/_commands.py` | `_resolve_hosted_adapter_ids()` constructs `GatewayHostedAdaptersSettings` instead of `Settings`. |
| `tests/unit/config/test_gateway_hosted_adapters_settings.py` (new) | Pure-function validator tests (incl. the symlink-escape containment branch) + minimal-model key-free / traversal / malformed-JSON tests + cross-model equivalence corpus. |
| `tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py` | Retarget the 5 monkeypatches `Settings` → `GatewayHostedAdaptersSettings` (quoted patch string only — NOT the module docstring). |
| `tests/unit/cli/gateway/test_gateway_start_adapter_ids.py` | Retarget the `Settings` monkeypatch (`:65`) → `GatewayHostedAdaptersSettings` (drives the resolver via `gateway start`; found by the plan-review fleet). |
| `tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py` | Tighten: key-free empty resolve; single- AND multi-segment traversal regression-lock; real key-free `["alfred_discord"]→["discord"]` positive resolve. |
| `tests/unit/cli/test_gateway_cli.py` | Two stale-docstring wording fixes (`Settings()` → `GatewayHostedAdaptersSettings()`). Autouse key fixture is harmless — leave it. |
| `tests/unit/cli/gateway/test_adapter_egress_mount.py`, `test_egress_relay_mount.py`, `test_egress_proxy_mount.py` | Drop the now-unnecessary key/env setenvs; fix the fixture comment (all THREE mount tests). |
| `tests/adversarial/capability_bypass/gateway_keyfree_traversal_refused.yaml` + `test_cap_2026_006_gateway_keyfree_traversal_refused.py` (new) | Release-blocking parity for the gateway sole-guard path (mirrors `cap-2026-005`). |
| `tests/e2e/_services.py` | Remove `alfred-gateway` from `XFAIL_SERVICES`; add `HEALTHY_APP_SERVICES`. |
| `tests/e2e/test_first_run_boot.py` | Un-xfail `test_gateway_is_healthy`; widen the classification union; restore its full health budget; fix the `_XFAIL_HEALTH_TIMEOUT_S` comment (core-only). |
| `tests/unit/e2e/test_services.py` | Update the partition test for the new bucket. |
| `docs/adr/0036-*.md` | One-line pointer to the key-free `GatewayHostedAdaptersSettings` pattern. |

---

## Task 1: Shared adapter-id validator + `GatewayHostedAdaptersSettings`

**Files:**

- Modify: `src/alfred/config/settings.py`
- Test: `tests/unit/config/test_gateway_hosted_adapters_settings.py` (create)

**Interfaces:**

- Produces: `validate_comms_adapter_ids(value: tuple[str, ...]) -> tuple[str, ...]` (module-level, raises `ValueError` on a bad id); `GatewayHostedAdaptersSettings` (a `BaseSettings` with one field `comms_enabled_adapters: tuple[str, ...]`, default `()`, whose construction lifts failures to `SettingsError`).
- Consumes: existing module-level `_COMMS_ADAPTER_ID_RE`, `_REPO_ROOT`, `SettingsError`.

- [ ] **Step 1: Write the failing test (pure function + minimal model + containment branch + equivalence)**

Create `tests/unit/config/test_gateway_hosted_adapters_settings.py`:

```python
"""#499: the shared adapter-id validator + the gateway's key-free hosted-adapters model.

`validate_comms_adapter_ids` is THE single source of truth for comms-adapter-id path-safety;
`GatewayHostedAdaptersSettings` is the gateway's key-free read of the allowlist (ADR-0036).
"""

from __future__ import annotations

import json
import sys

import pytest

from alfred.config.settings import (
    GatewayHostedAdaptersSettings,
    SettingsError,
    validate_comms_adapter_ids,
)

# The full bad-id corpus the SoT validator must reject, one entry per rejection branch.
_BAD_IDS = ["../../etc", "..", ".", "has space", "no_such_adapter"]


def test_validate_accepts_real_adapter_ids() -> None:
    # A real in-repo plugin-package id (plugins/alfred_discord/manifest.toml exists).
    assert validate_comms_adapter_ids(("alfred_discord",)) == ("alfred_discord",)
    assert validate_comms_adapter_ids(()) == ()


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_validate_rejects_bad_ids(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_comms_adapter_ids((bad,))


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlink creation needs privilege on Windows; the containment branch is "
    "coverage-measured on Linux CI",
)
def test_validate_rejects_symlink_escape(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fire the `is_relative_to` containment branch — the SOLE guard on the gateway path.

    A charset-clean id whose `plugins/<id>/manifest.toml` symlinks OUT of `plugins/` is the
    only way to reach this branch (the charset regex blocks `/`). This closes the
    pre-existing uncovered line ci.yml:715-729 cites as why settings.py is off the 100% gate.
    """
    from pathlib import Path

    root = Path(str(tmp_path))
    outside = root / "outside"
    outside.mkdir()
    (outside / "manifest.toml").write_text("", encoding="utf-8")
    plugins = root / "plugins"
    plugins.mkdir()
    (plugins / "escape").symlink_to(outside)  # plugins/escape -> root/outside
    monkeypatch.setattr("alfred.config.settings._REPO_ROOT", root)

    with pytest.raises(ValueError):
        validate_comms_adapter_ids(("escape",))


def test_gateway_model_resolves_empty_without_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of #499: read the allowlist with NO provider key and NO environment."""
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    assert GatewayHostedAdaptersSettings().comms_enabled_adapters == ()  # type: ignore[no-untyped-call]


def test_gateway_model_accepts_real_id_without_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["alfred_discord"]')

    assert GatewayHostedAdaptersSettings().comms_enabled_adapters == ("alfred_discord",)  # type: ignore[no-untyped-call]


def test_gateway_model_rejects_traversal_as_settings_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A traversal-shaped id lifts to SettingsError so start_gateway's config arm catches it."""
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '[".."]')
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]


def test_gateway_model_rejects_malformed_json_as_settings_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-JSON ALFRED_COMMS_ENABLED_ADAPTERS is a config fault, not a raw traceback.

    pydantic-settings JSON-decodes the tuple field inside __init__; a malformed value must
    lift to SettingsError (the fail-loud posture start_gateway's config arm depends on).
    """
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[unclosed")
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_both_models_reject_the_same_bad_ids(bad: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioural equivalence over the FULL corpus: both models delegate to one rule.

    Not tautological, and not single-input: a divergence on ANY branch (e.g. the is_file
    check) between the two field validators would red here — the drift the SoT guards against.
    """
    from alfred.config.settings import Settings

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", json.dumps([bad]))
    with pytest.raises(SettingsError):
        Settings()  # type: ignore[no-untyped-call]
    with pytest.raises(SettingsError):
        GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/config/test_gateway_hosted_adapters_settings.py -q`
Expected: FAIL — `ImportError: cannot import name 'GatewayHostedAdaptersSettings' / 'validate_comms_adapter_ids'`.

- [ ] **Step 3: Extract the validator into a module-level function**

In `src/alfred/config/settings.py`, add a module-level function just above `class SettingsError` (~line 123, with the module-level `_COMMS_ADAPTER_ID_RE` / `_REPO_ROOT` it uses). Copy the body **verbatim** from the existing `_validate_comms_enabled_adapters` (settings.py:465–486):

```python
def validate_comms_adapter_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    """Reject any adapter id that is mis-charset, traversal-shaped, or has no real manifest.

    THE single source of truth for comms-adapter-id path-safety (#499). Both ``Settings``
    (full core config) and ``GatewayHostedAdaptersSettings`` (the gateway's key-free read)
    delegate their ``comms_enabled_adapters`` field validator here, so the two can never
    drift (CLAUDE.md hard rule #7; security/_config_protocols.py). The ``is_relative_to``
    containment branch is the SOLE path-traversal guard on the gateway resolver path
    (``_resolve_adapter_kind`` does a bare ``read_text()`` with no sink re-check). The
    message stays raw English (no ``t()``): Settings loads too early in boot for the translator.
    """
    plugins_root = (_REPO_ROOT / "plugins").resolve()
    for adapter_id in value:
        if not _COMMS_ADAPTER_ID_RE.match(adapter_id):
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        if adapter_id in {".", ".."}:
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
        if not manifest_path.resolve().is_relative_to(plugins_root):
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        if not manifest_path.is_file():
            raise ValueError(f"no manifest for comms adapter id {adapter_id!r}")
    return value
```

- [ ] **Step 4: Make `Settings._validate_comms_enabled_adapters` delegate**

Replace the body of `_validate_comms_enabled_adapters` (settings.py:451–486) with a one-line delegation, keeping the method name + decorator (so the docstrings in `_config_protocols.py` / `_comms_adapter_grants.py` that reference it stay accurate):

```python
    @field_validator("comms_enabled_adapters")
    @classmethod
    def _validate_comms_enabled_adapters(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Delegate to the shared :func:`validate_comms_adapter_ids` (the SoT, #499)."""
        return validate_comms_adapter_ids(value)
```

- [ ] **Step 5: Add the shared `SettingsError`-lifting base and the minimal model**

Extract `Settings.__init__` (settings.py:553–558) into a shared base and make `Settings` inherit it, then add the minimal model. Add ABOVE `class Settings` (after `class SettingsError`):

```python
class _SettingsErrorLifting(BaseSettings):
    """Base that lifts any construction failure to :class:`SettingsError` (#499).

    Both ``Settings`` and ``GatewayHostedAdaptersSettings`` inherit this so a pydantic
    ``ValidationError`` (which is NOT a ``ValueError``) never escapes raw — the CLI catch
    sites (``_load_settings_or_die``, ``start_gateway``'s config arm at ``_commands.py:294``)
    depend on the single ``SettingsError`` type. The ``from exc`` chaining is preserved so
    ``daemon/_commands.py``'s ``exc.__cause__`` field-name reader still works.
    """

    def __init__(self, **kw):  # type: ignore[no-untyped-def]
        try:
            super().__init__(**kw)
        except Exception as exc:
            raise SettingsError(str(exc)) from exc
```

Change `class Settings(BaseSettings):` → `class Settings(_SettingsErrorLifting):` and DELETE the now-duplicated `Settings.__init__` (settings.py:553–558).

Add the minimal model at the END of the module (after `Settings`):

```python
class GatewayHostedAdaptersSettings(_SettingsErrorLifting):
    """The gateway's key-free read of the hosted-adapter allowlist (ADR-0036, #499).

    ONE field. The gateway holds no provider secret, so it MUST NOT construct the full
    ``Settings`` (whose ``deepseek_api_key`` is required-no-default). pydantic-settings does
    the ``ALFRED_COMMS_ENABLED_ADAPTERS`` env-read + JSON-decode natively; the shared
    :func:`validate_comms_adapter_ids` keeps path-safety identical to the full ``Settings``.
    ``extra="ignore"`` drops any provider key present in the env (ADR-0036 belt-and-braces).
    """

    model_config = SettingsConfigDict(
        env_prefix="ALFRED_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    comms_enabled_adapters: tuple[str, ...] = Field(default=())

    @field_validator("comms_enabled_adapters")
    @classmethod
    def _validate_comms_enabled_adapters(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return validate_comms_adapter_ids(value)
```

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `uv run pytest tests/unit/config/test_gateway_hosted_adapters_settings.py -q`
Expected: PASS (accepts-real + 5 bad-id params + symlink-escape + empty + real-id + traversal + malformed-JSON + 5 equivalence params).

- [ ] **Step 7: Run the existing settings + comms-adapter suites (no regression)**

Run: `uv run pytest tests/unit/config -q`
Expected: PASS — the delegation preserves `Settings` field-validation behavior byte-for-byte.

- [ ] **Step 8: Type-check + lint the changed module**

Run: `uv run mypy src/alfred/config/settings.py && uv run pyright src/alfred/config/settings.py && uv run ruff check src/alfred/config/settings.py && uv run ruff format --check src/alfred/config/settings.py`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/config/settings.py tests/unit/config/test_gateway_hosted_adapters_settings.py
git commit -m "$(cat <<'EOF'
refactor: #499 extract shared adapter-id validator + add GatewayHostedAdaptersSettings

One source of truth for comms-adapter-id path-safety (validate_comms_adapter_ids), with a
direct symlink-escape test for its containment branch (the sole guard on the gateway path);
a key-free one-field GatewayHostedAdaptersSettings (ADR-0036) sharing it, with a
_SettingsErrorLifting base so bad-id AND malformed-JSON construction faults lift to SettingsError.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
Claude-Session: https://claude.ai/code/session_01Dj5hUg5NDaYrPDU2Rbs3QS
EOF
)"
```

---

## Task 2: Point the gateway resolver at the minimal model

**Files:**

- Modify: `src/alfred/cli/gateway/_commands.py:143-159`
- Test: `tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py`, `tests/unit/cli/gateway/test_gateway_start_adapter_ids.py`, `tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py`
- Modify (wording/setup): `tests/unit/cli/test_gateway_cli.py`, `tests/unit/cli/gateway/test_adapter_egress_mount.py`, `test_egress_relay_mount.py`, `test_egress_proxy_mount.py`

**Interfaces:**

- Consumes: `alfred.config.settings.GatewayHostedAdaptersSettings` (Task 1).
- Produces: `_resolve_hosted_adapter_ids() -> list[str]` (unchanged signature; now key-free).

- [ ] **Step 1: Rewrite the resolver test to prove key-free posture + lock traversal + real positive resolve (write failing tests first)**

Rewrite `tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py`:

```python
"""#499: the gateway resolver reads ALFRED_COMMS_ENABLED_ADAPTERS with NO provider key.

Proves the whole chain — compose default -> shell env -> pydantic-settings JSON-decode ->
`_resolve_hosted_adapter_ids` -> canonical ids — end to end WITHOUT a provider key or
environment (the ADR-0036 posture #499 delivers), that the path-traversal guard is intact
(single- AND multi-segment), and that a real id resolves to its canonical kind.
"""

from __future__ import annotations

import pytest

from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids
from alfred.config.settings import SettingsError


def _key_free_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)


def test_resolve_hosted_adapter_ids_empty_is_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    """`ALFRED_COMMS_ENABLED_ADAPTERS=[]` -> `[]` with NO ALFRED_DEEPSEEK_API_KEY / ENVIRONMENT."""
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    assert _resolve_hosted_adapter_ids() == []


def test_resolve_hosted_adapter_ids_real_id_maps_to_canonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A REAL id from env, no key: `["alfred_discord"]` -> `["discord"]` (canonical).

    Unlike the stubbed reconciliation tests, this drives real env-decode + validation +
    `_resolve_adapter_kind` (spec item 3 — the key-free positive resolve).
    """
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["alfred_discord"]')

    assert _resolve_hosted_adapter_ids() == ["discord"]


@pytest.mark.parametrize("traversal", ['["../../etc"]', '[".."]'])
def test_resolve_hosted_adapter_ids_rejects_traversal(
    traversal: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Traversal ids are refused BEFORE `_resolve_adapter_kind` reads a manifest.

    Both the multi-segment (`../../etc`, caught by the charset regex) AND the single-segment
    (`..`, caught by the FIX-3 branch) — so deleting either guard reds this. The
    `_resolve_adapter_kind` read sink has no sink-local re-check, so the construction-time
    validator is the sole guard; this locks it in after the decoupling.
    """
    _key_free_env(monkeypatch)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", traversal)

    with pytest.raises(SettingsError):
        _resolve_hosted_adapter_ids()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py -q`
Expected: FAIL — the empty + real-id tests error because the OLD `_resolve_hosted_adapter_ids` builds a full `Settings()` that now raises `SettingsError` on the missing `ALFRED_DEEPSEEK_API_KEY` (proving the resolver still needs the key — the bug we fix next). The traversal test passes for the wrong reason (missing key) until Step 3.

- [ ] **Step 3: Switch the resolver to the minimal model**

In `src/alfred/cli/gateway/_commands.py`, replace `_resolve_hosted_adapter_ids` (143–159). Note the `# type: ignore[no-untyped-call]` carried over from the old `Settings()` construction (`:157`) — mypy `no-untyped-call` re-fires on the inherited untyped `__init__` without it:

```python
def _resolve_hosted_adapter_ids() -> list[str]:
    """The gateway-hosted (bwrap-spawned) adapter subset from settings (G6-5 Task 7/10, #288).

    Sources the configured comms-adapter allowlist from
    :attr:`alfred.config.settings.GatewayHostedAdaptersSettings.comms_enabled_adapters` (env
    ``ALFRED_COMMS_ENABLED_ADAPTERS``, holding plugin-package ids) — the gateway's KEY-FREE
    read (ADR-0036 / #499): it must NOT construct the full ``Settings`` (whose required
    ``deepseek_api_key`` the gateway is denied). Maps each id through the
    :func:`_resolve_adapter_kind` reconciliation seam to its canonical ``adapter_id`` and
    EXCLUDES the TUI dial-in kind — the TUI dials the gateway, it is not a spawned adapter.
    An empty / TUI-only set yields ``[]`` so the supervisor is a clean no-op.
    """
    from alfred.config.settings import GatewayHostedAdaptersSettings

    settings = GatewayHostedAdaptersSettings()  # type: ignore[no-untyped-call]  # BaseSettings __init__ is untyped
    resolved = (_resolve_adapter_kind(a) for a in settings.comms_enabled_adapters)
    return [kind for kind in resolved if kind != _TUI_DIAL_IN_ADAPTER_ID]
```

- [ ] **Step 4: Run the resolver test to verify it passes**

Run: `uv run pytest tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py -q`
Expected: PASS (empty + real-id + 2 traversal params).

- [ ] **Step 5: Retarget the reconciliation-test monkeypatches (quoted string only)**

In `tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py`, retarget the 5 `monkeypatch.setattr("alfred.config.settings.Settings", ...)` sites. Use the QUOTED patch string so the sed hits ONLY the 5 patch literals and NOT the line-6 module docstring `alfred.config.settings.Settings.comms_enabled_adapters` (a general truth that must stay):

Run: `sed -i '' 's/"alfred\.config\.settings\.Settings"/"alfred.config.settings.GatewayHostedAdaptersSettings"/g' tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py`

Verify exactly the 5 patch sites changed and the docstring is untouched:

Run: `grep -n 'GatewayHostedAdaptersSettings"' tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py; grep -n 'Settings\.comms_enabled_adapters' tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py`
Expected: 5 quoted `GatewayHostedAdaptersSettings"` patch lines; the line-6 docstring still reads `Settings.comms_enabled_adapters`.

- [ ] **Step 6: Retarget `test_gateway_start_adapter_ids.py` (plan-review High)**

This file drives the resolver via `gateway start` and patches `Settings` at `:65` (it does NOT contain the literal `_resolve_hosted_adapter_ids`, so the earlier grep missed it — `test_start_threads_enabled_adapters_into_adapter_ids` + `test_start_keeps_a_mixed_set_minus_tui` assert `["discord"]`).

Run: `sed -i '' 's/"alfred\.config\.settings\.Settings"/"alfred.config.settings.GatewayHostedAdaptersSettings"/g' tests/unit/cli/gateway/test_gateway_start_adapter_ids.py`

Verify:

Run: `grep -n 'alfred.config.settings' tests/unit/cli/gateway/test_gateway_start_adapter_ids.py`
Expected: the `:65` patch now targets `...GatewayHostedAdaptersSettings`; no bare `...Settings"` patch remains.

- [ ] **Step 7: Fix the two stale docstrings in `test_gateway_cli.py`**

Update the two docstrings that say `Settings()` (behavior is unchanged — the autouse `_env` key fixture is now a harmless leftover, leave it):

Edit `test_start_canonical_discord_typo_is_config_fault_not_traceback` (line ~276) — replace:

```
    disk, so ``Settings()`` construction (inside ``_resolve_hosted_adapter_ids``) raises
```

with:

```
    disk, so ``GatewayHostedAdaptersSettings()`` construction (inside
    ``_resolve_hosted_adapter_ids``) raises
```

Edit `test_start_unrelated_resolve_error_still_surfaces_loud` (line ~297) — replace:

```
    ``Settings.__init__`` lifts every construction exception to ``SettingsError``, so this
    control must raise from a step AFTER ``Settings()`` succeeds — ``_resolve_adapter_kind``,
```

with:

```
    ``GatewayHostedAdaptersSettings.__init__`` (via ``_SettingsErrorLifting``) lifts every
    construction exception to ``SettingsError``, so this control must raise from a step AFTER
    it succeeds — ``_resolve_adapter_kind``,
```

- [ ] **Step 8: Simplify the THREE mount-test fixtures (drop the now-unnecessary key/env)**

The autouse `_env` fixtures set the provider key/environment ONLY because the OLD resolver built a full `Settings()`. Remove those two setenv lines and fix the comment in ALL THREE mount tests; KEEP the adapter-var clearing (still needed so the resolve yields `[]` and does not divert to `config_failed`).

`test_egress_relay_mount.py` — replace:

```python
    # _resolve_hosted_adapter_ids() (in start) constructs Settings(), which needs the
    # provider key + environment. The relay itself NEVER constructs Settings.
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
```

with:

```python
    # _resolve_hosted_adapter_ids() (in start) constructs the key-free
    # GatewayHostedAdaptersSettings (ADR-0036 / #499) — no provider key needed.
```

`test_adapter_egress_mount.py` — replace the fixture docstring + the two setenvs:

```python
    """Minimal env for ``start_gateway``.

    ``_resolve_hosted_adapter_ids()`` constructs ``Settings()``, which requires the
    provider key + environment. The adapter proxy itself never constructs Settings.
    Relay / proxy resolvers' defaults are pinned; the hosted-adapter set is cleared so
    the test does not divert to ``config_failed``.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
```

with:

```python
    """Minimal env for ``start_gateway``.

    ``_resolve_hosted_adapter_ids()`` constructs the key-free
    ``GatewayHostedAdaptersSettings`` (ADR-0036 / #499) — no provider key needed. Relay /
    proxy resolvers' defaults are pinned; the hosted-adapter set is cleared so the test
    does not divert to ``config_failed``.
    """
```

`test_egress_proxy_mount.py` — this sibling has the identical `ALFRED_DEEPSEEK_API_KEY`/`ALFRED_ENVIRONMENT` setenv (`:32`) + stale comment. Apply the SAME treatment: remove the two setenvs, update the comment to name the key-free `GatewayHostedAdaptersSettings`, keep the adapter-var clearing. (Read the fixture first to match its exact comment text.)

- [ ] **Step 9: Run the full gateway CLI + mount suites (no regression)**

Run: `uv run pytest tests/unit/cli/test_gateway_cli.py tests/unit/cli/gateway -q`
Expected: PASS (all gateway CLI + resolver + reconciliation + start-adapter-ids + mount tests).

- [ ] **Step 10: Type-check + lint the changed files**

Run: `uv run mypy src/alfred/cli/gateway/_commands.py && uv run pyright src/alfred/cli/gateway/_commands.py && uv run ruff check src/alfred/cli/gateway tests/unit/cli/gateway tests/unit/cli/test_gateway_cli.py && uv run ruff format --check src/alfred/cli/gateway/_commands.py`
Expected: no errors.

- [ ] **Step 11: Commit**

```bash
git add src/alfred/cli/gateway/_commands.py tests/unit/cli/gateway/test_hosted_adapter_id_reconciliation.py tests/unit/cli/gateway/test_gateway_start_adapter_ids.py tests/unit/cli/gateway/test_resolve_hosted_adapter_ids_empty_env.py tests/unit/cli/test_gateway_cli.py tests/unit/cli/gateway/test_adapter_egress_mount.py tests/unit/cli/gateway/test_egress_relay_mount.py tests/unit/cli/gateway/test_egress_proxy_mount.py
git commit -m "$(cat <<'EOF'
fix: #499 gateway resolves hosted adapters without a provider key (ADR-0036)

_resolve_hosted_adapter_ids builds the key-free GatewayHostedAdaptersSettings instead of a
full Settings(); the path-traversal guard is unchanged (shared validator) and pinned by a
single- and multi-segment resolver-level regression-lock + a real key-free positive resolve.
Dependent gateway tests (reconciliation, start-adapter-ids, mounts) retargeted to the new model.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
Claude-Session: https://claude.ai/code/session_01Dj5hUg5NDaYrPDU2Rbs3QS
EOF
)"
```

---

## Task 3: Adversarial-corpus parity for the gateway sole-guard path

**Files:**

- Create: `tests/adversarial/capability_bypass/gateway_keyfree_traversal_refused.yaml`
- Create: `tests/adversarial/capability_bypass/test_cap_2026_006_gateway_keyfree_traversal_refused.py`

**Why:** the daemon builder path has `cap-2026-005` (sink-local containment). The gateway resolver path is the MORE weakly-guarded one — its only guard is the construction-time validator (`_resolve_adapter_kind` has no sink re-check) — yet has no release-blocking coverage. This pins the sole-guard property at the adversarial (release-blocking) layer, symmetric with the daemon path.

- [ ] **Step 1: Author the corpus entry via the adversarial-corpus skill**

Invoke the `alfred-adversarial-corpus` skill for the exact YAML schema + loader wiring, modelled on the existing `cap-2026-005` pair. Target content:

`gateway_keyfree_traversal_refused.yaml`:

```yaml
id: cap-2026-012
category: capability_bypass
threat: "A traversal-shaped comms-adapter id in the gateway's key-free ALFRED_COMMS_ENABLED_ADAPTERS reaches the gateway resolver's _resolve_adapter_kind manifest read sink (which has NO sink-local containment re-check, unlike the daemon builder), escaping the plugins/ directory to read an arbitrary manifest.toml off the host."
ingestion_path: capability_gate
payload:
  resolver: gateway_hosted_adapters
  enabled_adapter_id: "../../../../etc"
  attempted_action: read_manifest_outside_plugins
expected_outcome: refused
provenance: "#499 decoupled the gateway's hosted-adapter read from full Settings() into GatewayHostedAdaptersSettings (ADR-0036, no provider key). Path-traversal safety on the gateway resolver path rests ENTIRELY on the construction-time comms_enabled_adapters validator (the shared validate_comms_adapter_ids: charset, ./.. rejection, plugins/ containment, is_file) — unlike the daemon builder (cap-2026-005), _resolve_adapter_kind at _commands.py does a bare read_text() with NO sink re-check. A traversal-shaped id must be REFUSED at model construction (SettingsError, mapped by start_gateway's config arm to _EXIT_CONFIG_FAILED) before it ever reaches the read sink. This entry pins the sole-guard property at the release-blocking layer, symmetric with cap-2026-005's belt-and-braces daemon path."
references:
  - "ADR-0036"
  - "issue #499"
  - "issue #364"
  - "CLAUDE.md hard rule #7"
  - "cap-2026-005"
```

`test_cap_2026_006_gateway_keyfree_traversal_refused.py` — mirror the `cap-2026-005` test shape (corpus-filter fixture with the missing/duplicate drift-guard), driving the REAL production `_resolve_hosted_adapter_ids` (NEVER a shim). The assertion body:

```python
def test_gateway_keyfree_traversal_refused(
    gateway_traversal_payload: AdversarialPayload, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)  # key-free posture (ADR-0036)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv(
        "ALFRED_COMMS_ENABLED_ADAPTERS", json.dumps([gateway_traversal_payload.enabled_adapter_id])
    )
    # Refused at construction (SettingsError) BEFORE _resolve_adapter_kind's read sink.
    with pytest.raises(SettingsError):
        _resolve_hosted_adapter_ids()
    # Positive control: a real in-repo id resolves (the guard is not "reject everything").
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["alfred_comms_test"]')
    assert _resolve_hosted_adapter_ids() == ["alfred_comms_test"]
```

- [ ] **Step 2: Run the new adversarial entry**

Run: `uv run pytest tests/adversarial/capability_bypass/test_cap_2026_006_gateway_keyfree_traversal_refused.py -q`
Expected: PASS.

- [ ] **Step 3: Lint + commit**

Run: `uv run ruff check tests/adversarial/capability_bypass && uv run ruff format --check tests/adversarial/capability_bypass/test_cap_2026_006_gateway_keyfree_traversal_refused.py`

```bash
git add tests/adversarial/capability_bypass/gateway_keyfree_traversal_refused.yaml tests/adversarial/capability_bypass/test_cap_2026_006_gateway_keyfree_traversal_refused.py
git commit -m "$(cat <<'EOF'
test: #499 adversarial parity for the gateway key-free traversal-refusal (cap-2026-012)

The gateway resolver path's sole guard is the construction-time validator (no sink re-check,
unlike the daemon builder's cap-2026-005). Pins that a traversal-shaped ALFRED_COMMS_ENABLED_ADAPTERS
id is refused at construction, at the release-blocking layer.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
Claude-Session: https://claude.ai/code/session_01Dj5hUg5NDaYrPDU2Rbs3QS
EOF
)"
```

---

## Task 4: The #494 e2e ratchet (un-xfail the gateway)

**Files:**

- Modify: `tests/e2e/_services.py`
- Modify: `tests/e2e/test_first_run_boot.py`
- Test: `tests/unit/e2e/test_services.py`

**Interfaces:**

- Produces: `_services.HEALTHY_APP_SERVICES: frozenset[str]` (services graduated from XFAIL to "asserted healthy by a dedicated build-required test").

- [ ] **Step 1: Write the failing unit test for the new partition**

Replace `test_baseline_and_xfail_partition_covers_the_six` in `tests/unit/e2e/test_services.py` (lines 24–36) with a three-bucket partition test:

```python
def test_baseline_app_and_xfail_partition_covers_the_six() -> None:
    # Disjoint AND covering = a genuine partition across the three buckets (CR: assert
    # pairwise-disjoint, not just the union — a service mis-classified into two buckets
    # would still satisfy the union alone).
    baseline = _services.BASELINE_SERVICES
    app = _services.HEALTHY_APP_SERVICES
    xfail = set(_services.XFAIL_SERVICES)
    assert baseline.isdisjoint(app)
    assert baseline.isdisjoint(xfail)
    assert app.isdisjoint(xfail)
    known = baseline | app | xfail
    assert known == {
        "alfred-postgres",
        "alfred-redis",
        "alfred-prometheus",
        "alfred-grafana",
        "alfred-gateway",
        "alfred-core",
    }
    # The ratchet has advanced: the gateway is asserted-healthy, only core remains xfail.
    assert app == {"alfred-gateway"}
    assert xfail == {"alfred-core"}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/unit/e2e/test_services.py -q`
Expected: FAIL — `AttributeError: module 'tests.e2e._services' has no attribute 'HEALTHY_APP_SERVICES'`.

- [ ] **Step 3: Update `_services.py` — new bucket, gateway out of XFAIL**

In `tests/e2e/_services.py`, replace the `XFAIL_SERVICES` block (lines 21–26):

```python
# Services graduated from XFAIL to "asserted healthy by a dedicated build-required test"
# (NOT the pulled-image infra baseline the boot_stack fixture co-boots). Grows as blockers
# land; the ratchet advances XFAIL -> HEALTHY_APP one service at a time.
HEALTHY_APP_SERVICES: frozenset[str] = frozenset({"alfred-gateway"})

# Known-blocked services -> the roadmap issue that un-blocks them. Shrinks toward empty as
# blockers land (the ratchet). alfred-gateway graduated to HEALTHY_APP_SERVICES at #499.
XFAIL_SERVICES: Mapping[str, str] = {
    "alfred-core": "#500",
}
```

- [ ] **Step 4: Update the e2e classification test, un-xfail the gateway, fix the stale timeout comment**

In `tests/e2e/test_first_run_boot.py`:

(a) Widen the classification union in `test_every_compose_service_is_classified` (line 51):

```python
    known = (
        _services.BASELINE_SERVICES
        | _services.HEALTHY_APP_SERVICES
        | set(_services.XFAIL_SERVICES)
    )
```

(b) Remove the `@pytest.mark.xfail(...)` decorator on `test_gateway_is_healthy` (lines 58–62) and restore the full health budget by dropping the `timeout_s` override (line 74). The test becomes:

```python
def test_gateway_is_healthy(boot_stack: BootStack) -> None:
    # #499 landed: the gateway resolves its hosted-adapter allowlist without a provider key
    # (ADR-0036), so it boots healthy standalone (core absent -> healthy-while-buffering).
    _compose.compose(
        boot_stack.project,
        "up",
        "-d",
        "--no-deps",
        "alfred-gateway",
        env_file=boot_stack.env_file,
        timeout_s=_UP_TIMEOUT_S,
    )
    assert boot_stack.health("alfred-gateway") is ServiceHealth.HEALTHY
```

(c) Fix the now-stale `_XFAIL_HEALTH_TIMEOUT_S` comment (lines 30–33) — only core remains xfail:

```python
# The core xfail test polls a SHORTER health budget: its blocker (#500) crash-loops as a
# perpetual `starting` and can never resolve early, so the full 180s baseline budget would just
# burn ~6 min/nightly (review: performance). Restore the full budget when Step 3 un-xfails core.
_XFAIL_HEALTH_TIMEOUT_S = 60.0
```

- [ ] **Step 5: Run the unit services test to verify it passes**

Run: `uv run pytest tests/unit/e2e/test_services.py -q`
Expected: PASS.

- [ ] **Step 6: Lint + type-check the e2e changes**

Run: `uv run ruff check tests/e2e tests/unit/e2e && uv run ruff format --check tests/e2e/_services.py tests/e2e/test_first_run_boot.py && uv run mypy tests/e2e/_services.py`
Expected: no errors. (The e2e boot tests themselves are nightly/docker-gated — verified live in Task 5.)

- [ ] **Step 7: Commit**

```bash
git add tests/e2e/_services.py tests/e2e/test_first_run_boot.py tests/unit/e2e/test_services.py
git commit -m "$(cat <<'EOF'
test: #499 ratchet the #494 e2e lane — assert alfred-gateway healthy (un-xfail)

Gateway graduates XFAIL_SERVICES -> new HEALTHY_APP_SERVICES bucket; test_gateway_is_healthy
drops its strict-xfail and asserts healthy on the full budget; classification union + the
unit partition test widened; the _XFAIL_HEALTH_TIMEOUT_S comment now names core only.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
Claude-Session: https://claude.ai/code/session_01Dj5hUg5NDaYrPDU2Rbs3QS
EOF
)"
```

---

## Task 5: Full gates, live gateway-boot verification, ADR note, open PR

**Files:** `docs/adr/0036-*.md` (one-line note) + verification + PR.

- [ ] **Step 1: Add the ADR-0036 pointer for the key-free pattern**

Append a one-line Consequences note to the ADR-0036 file (`docs/adr/0036-gateway-adapter-hosting-inversion.md`) so a future reader does not re-reach for `Settings()`:
> The gateway reads its hosted-adapter allowlist via `GatewayHostedAdaptersSettings` (a one-field, key-free `BaseSettings`; #499), never the full `Settings` — which requires the provider secret this ADR denies the gateway.

Run markdownlint on the touched ADR: `npx --yes markdownlint-cli2@0.22.1 "docs/adr/0036-*.md"`
Expected: no errors.

- [ ] **Step 2: Run the full quality gates**

Run: `make check`
Expected: lint + format + mypy + pyright + unit all green. If the macOS integration lane flakes under load (mass testcontainers errors), verify suspects in isolation and trust Linux CI (per project memory).

- [ ] **Step 3: Run the full adversarial suite (security-adjacent change)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS — incl. the existing `cap-2026-005` (validator behavior unchanged) and the new `cap-2026-012` (gateway key-free traversal refusal).

- [ ] **Step 4: Live-verify the gateway boots healthy with NO provider key (MANDATORY pre-merge)**

Build + bring up ONLY the gateway (mirrors the e2e `test_gateway_is_healthy`), confirming it reaches `healthy` standalone with the stock `.env` (no `ALFRED_DEEPSEEK_API_KEY` reaching it). **This manual confirmation is required before merge** — the e2e assertion is nightly-only, so this is the pre-merge signal that the gateway is genuinely standalone-healthy (the per-PR unit tests prove the key-free *resolve*; this proves container *health*). Do NOT promote the e2e lane to a required gate — that is roadmap Step 5.

```bash
# Linux (the nightly environment): load the alfred-bwrap AppArmor profile the gateway pins,
# or Docker refuses to create the container. (On macOS Docker Desktop the apparmor= security_opt
# is a silent no-op, so a green macOS run does NOT represent the nightly Linux env — treat a
# macOS pass as indicative only; the authoritative signal is the Linux nightly.)
[ "$(uname)" = "Linux" ] && sudo apparmor_parser -r -W docker/apparmor/alfred-bwrap 2>/dev/null || true

docker compose build alfred-gateway
docker compose up -d --no-deps alfred-gateway
for i in $(seq 1 20); do
  status=$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q alfred-gateway)" 2>/dev/null || echo "none")
  echo "health=$status"; [ "$status" = "healthy" ] && break; sleep 3
done
docker compose logs alfred-gateway | tail -40
docker compose down
```

Expected: `health=healthy`. If it stalls at `starting`/`unhealthy`, read the logs — if the gateway needs Redis (or any `--no-deps`-omitted service) to reach healthy, that is a NEW finding the harness diagnosis did not name; STOP and apply superpowers:systematic-debugging (do not pre-solve). If the container fails to CREATE on Linux, confirm the AppArmor profile loaded (the step above). Otherwise the standalone-healthy premise is confirmed.

- [ ] **Step 5: Confirm no i18n / catalog drift**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred-499.pot src/alfred plugins && echo "extract OK — this PR adds no t() strings; the validator stays raw English by existing convention"`
Expected: extract succeeds; no new catalog entries.

- [ ] **Step 6: Push the branch and open the PR**

```bash
git push -u origin 499-gateway-settings-decoupling
gh pr create --base main --title "fix: #499 gateway resolves hosted adapters without a provider key (roadmap #469 Step 2)" --body "$(cat <<'EOF'
Roadmap #469 Step 2. Decouples `_resolve_hosted_adapter_ids()` from a full `Settings()` so the
gateway reads `comms_enabled_adapters` without the provider key it is denied (ADR-0036), via a
minimal `GatewayHostedAdaptersSettings` sharing the security-critical adapter-id validator.

Flips the #494 nightly `test_gateway_is_healthy` xfail to an assert-healthy (the intended ratchet);
`alfred-gateway` graduates `XFAIL_SERVICES` -> new `HEALTHY_APP_SERVICES`. Only `alfred-core` (#500)
remains xfail.

Security: the path-traversal guard on the gateway adapter-id read is unchanged (one shared
validator; `_resolve_adapter_kind`'s read sink has no sink-local re-check, so the construction-time
validator is the sole guard — pinned by a single/multi-segment resolver-level regression-lock, a
direct symlink-escape test on the containment branch, and a new release-blocking adversarial entry
`cap-2026-012`). Full adversarial suite green.

Spec: `docs/superpowers/specs/2026-07-25-499-gateway-settings-decoupling-design.md`
Plan: `docs/superpowers/plans/2026-07-25-499-gateway-settings-decoupling.md`

Closes #499.

https://claude.ai/code/session_01Dj5hUg5NDaYrPDU2Rbs3QS
EOF
)"
```

- [ ] **Step 7: Run the review gauntlet before merge**

Per the standing cadence: run the full `/review-pr` fleet (security ALWAYS) + CodeRabbit (both), resolve every thread (reply-and-resolve with a sound rationale for any decline), then `gh pr merge --rebase` (NEVER `--admin`; the repo is rebase-only).

---

## Definition of Done

1. `alfred-gateway` reaches Docker `healthy` with no provider key — verified live (Task 5 Step 4, mandatory pre-merge) and via the un-xfailed nightly `test_gateway_is_healthy`.
2. The path-traversal guard on the gateway adapter-id path is provably intact: the resolver-level single/multi-segment regression-lock, the direct symlink-escape test on the `is_relative_to` containment branch, and the `cap-2026-012` adversarial entry.
3. One definition of the adapter-id validator; `Settings` and `GatewayHostedAdaptersSettings` share `validate_comms_adapter_ids`; equivalence pinned over the full bad-id corpus.
4. `make check` green; full adversarial suite green (incl. `cap-2026-012`); no i18n drift.
5. `XFAIL_SERVICES == {"alfred-core": "#500"}`; `HEALTHY_APP_SERVICES == {"alfred-gateway"}`.
6. PR through `/review-pr` fleet + CodeRabbit, all threads resolved, rebase-merged.
