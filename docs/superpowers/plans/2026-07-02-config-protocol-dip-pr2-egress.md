# Config-consumer DIP — PR2 (egress) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Narrow the `egress/client.py` config consumer (`EgressClient.from_settings`) from the concrete `Settings` god-object to a narrow read-only `EgressProxyConfig` Protocol reading only `egress_proxy_url`. First **validator-coupled** batch: `egress_proxy_url` carries a `mode="before"` normalizer (`_normalize_egress_proxy_url`, blank→None), so the Protocol docstrings the producer invariant and the existing real-`Settings` normalizer test is retained untouched.

**Architecture:** Add `src/alfred/egress/_config_protocols.py` with a single `@property`-based read-only `Protocol` (`EgressProxyConfig`) exposing only `egress_proxy_url: str | None`. Re-type `EgressClient.from_settings`'s parameter to consume it (rename `settings` → `config`; method name unchanged — the composition root still passes a real `Settings`). Real `Settings` satisfies the Protocol structurally (PEP 544), so the sole caller (`cli/_bootstrap.py`, composition root) is unchanged and there is **zero runtime behaviour change**. A committed mypy-checked identity-return function proves `Settings` satisfies the Protocol; a stub-based unit test proves the DIP win (the seam works against a trivial double). The `docs/python-conventions.md` convention already landed in PR1.

**Tech Stack:** Python 3.12+, Pydantic v2, `httpx`, `typing.Protocol`, pytest + pytest-asyncio, mypy `--strict`, pyright, ruff.

## Global Constraints

- **Design source of truth:** `docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md` (#351).
- **Zero runtime behaviour change for every real `Settings` input.** Primarily a typing/DIP refactor. The one runtime touch — hardening the fail-closed guard from `is None` to a full blank check (`not (proxy_url and proxy_url.strip())`, rejecting `None`/`""`/whitespace-only) per the security-lens plan review + the PR-review round — is observably identical for any real `Settings` (which never yields a blank value; the `mode="before"` normalizer collapses blank/whitespace→None), and a strict fail-closed *strengthening* only for the off-type stub domain the narrowing newly admits. Existing tests pass unchanged.
- **`Settings` is not modified.** It stays a `BaseSettings`; it only *satisfies* the new Protocol.
- **Boundary:** only leaf consumers narrow; the composition root (`cli/_bootstrap.py`, `bootstrap/`, loader, `Settings` def) keeps concrete `Settings`. `EgressClient.from_settings` is a leaf consumer (reads exactly one field).
- **Validator-coupling rule (this batch's wrinkle).** `egress_proxy_url` has a `mode="before"` normalizer `_normalize_egress_proxy_url` (`settings.py:344`, blank/whitespace → `None`). Per the design's validator-coupling rule the Protocol **docstrings the producer invariant** (a `Settings`-sourced value is already blank-normalized; a raw stub is not) and the existing real-`Settings` normalizer test (`tests/unit/config/test_settings_egress_proxy_url.py`) is **retained untouched** — a plain stub bypasses the normalizer, so that file is the validator-retention evidence. This PR adds NO Settings-construction test of its own; it relies on the existing one.
- **Read-only intent via `@property`** getters; satisfied by `Settings`' attribute and a plain stub.
- **Sole consumer.** `grep -rn egress_proxy_url src/alfred/` → only `settings.py` (field + normalizer) and `egress/client.py` (the consumer). `allowlist.py` takes a base-URL *string*, not `Settings` (ADR-0036) — NOT a consumer.
- **Sole caller.** `grep -rn 'EgressClient.from_settings' src/` → only `cli/_bootstrap.py:144`, a positional call passing a real `Settings`. No keyword-arg `settings=` caller exists, so the param rename is safe.
- **Modern typing:** PEP 604/585/695; no `Optional[X]`/`typing.List`; `from __future__ import annotations` at file top (matches the repo).
- **Commit trailer (every commit):**

  ```
  MrReasonable <4990954+MrReasonable@users.noreply.github.com>
  Claude-Session: https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
  ```

- **Conventional Commits** with a literal `#351` in every commit subject.
- **Branch:** `351-config-dip-egress` (already checked out off `origin/main`).

---

## File Structure

- `src/alfred/egress/_config_protocols.py` — **Create.** Holds `EgressProxyConfig` (the subsystem's narrow config Protocols module).
- `src/alfred/egress/client.py` — **Modify.** Re-type `from_settings`'s param (`settings: Settings` → `config: EgressProxyConfig`), drop the now-unused `TYPE_CHECKING` `Settings` import, `s/settings/config/` in the body + docstring prose.
- `tests/unit/egress/test_config_protocol_proof.py` — **Create.** The mechanism-proof (`Settings` satisfies) + a plain-stub DIP-win test that drives `EgressClient.from_settings` against a trivial double.
- `tests/unit/config/test_settings_egress_proxy_url.py` — **Untouched (retained).** The validator-retention evidence for the normalizer; do NOT edit.
- `tests/unit/egress/test_egress_client.py` — **Untouched.** Its `Settings.model_construct(...)`-based tests still pass (real `Settings` satisfies the narrowed param) and provide real-`Settings` behavioural coverage of the seam.

---

### Task 1: `EgressProxyConfig` Protocol + the structural-satisfaction proof

**Files:**

- Create: `src/alfred/egress/_config_protocols.py`
- Create: `tests/unit/egress/test_config_protocol_proof.py`

**Interfaces:**

- Produces: `alfred.egress._config_protocols.EgressProxyConfig` — a `Protocol` with a read-only `egress_proxy_url: str | None` property. Consumed by Task 2 (`client.py`) and the proof test.

- [ ] **Step 1: Write the Protocol module**

Create `src/alfred/egress/_config_protocols.py`:

```python
"""Narrow read-only config Protocols for the egress subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol

# Future egress-plane config Protocols (e.g. an ``EgressRelayConfig`` reading
# ``egress_relay_url`` for the web_fetch/relay batch, #351 PR4) belong in THIS module —
# don't mint a second per-field module.


class EgressProxyConfig(Protocol):
    """The config surface ``EgressClient.from_settings`` reads: the L7-proxy URL.

    Producer invariant: ``Settings.egress_proxy_url`` is normalized by
    ``_normalize_egress_proxy_url`` (``mode="before"``) so a blank/whitespace value
    deserializes to ``None`` — a ``Settings``-sourced value is therefore either a
    non-blank URL or ``None``, never a blank string. A plain stub bypasses that
    normalizer, so a stub *may* legally supply a blank string; the consumer therefore
    self-defends (``from_settings`` treats any blank value — ``None``, ``""``, or
    whitespace-only — as fail-closed, G7-3, ADR-0042). The "no route without a proxy"
    fail-closed invariant is owned by ``EgressClient.from_settings``, not by this
    config surface.
    """

    @property
    def egress_proxy_url(self) -> str | None: ...
```

- [ ] **Step 2: Write the proof + stub DIP-win test**

Create `tests/unit/egress/test_config_protocol_proof.py`:

```python
"""Structural-satisfaction proof for the egress config Protocol (#351).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> EgressProxyConfig`` iff ``Settings`` satisfies the
Protocol, so a real ``Settings`` can be passed wherever ``EgressProxyConfig`` is
required — and a future ``Settings.egress_proxy_url`` rename fails the type-check
instead of silently drifting. The stub tests prove the DIP win: the ``from_settings``
seam works against a trivial double, not just a full ``Settings``.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings
from alfred.egress._config_protocols import EgressProxyConfig
from alfred.egress.client import EgressClient
from alfred.egress.errors import IOPlaneUnavailableError


def _settings_satisfies(settings: Settings) -> EgressProxyConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


class _StubCfg:
    """A trivial config double — NOT a Settings — supplying the one field the seam reads."""

    def __init__(self, *, egress_proxy_url: str | None) -> None:
        self.egress_proxy_url = egress_proxy_url


def test_plain_stub_satisfies_egress_proxy_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""
    cfg: EgressProxyConfig = _StubCfg(egress_proxy_url="http://alfred-gateway:8889")
    assert cfg.egress_proxy_url == "http://alfred-gateway:8889"


def test_from_settings_accepts_a_plain_stub() -> None:
    """from_settings consumes EgressProxyConfig — a stub drives the seam end-to-end."""
    client = EgressClient.from_settings(_StubCfg(egress_proxy_url="http://alfred-gateway:8889"))
    assert client.proxy_url == "http://alfred-gateway:8889"


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_from_settings_blank_proxy_fails_closed(blank: str | None) -> None:
    """Fail-closed (G7-3, ADR-0042) holds for every blank value against the narrow Protocol.

    Narrowing the param to EgressProxyConfig admits an unnormalized stub value (a blank
    string) that a real Settings never produces (the mode="before" normalizer collapses
    blank/whitespace->None); the consumer self-defends against None, "", and whitespace-only
    so a blank proxy URL never silently builds a client.
    """
    with pytest.raises(IOPlaneUnavailableError):
        EgressClient.from_settings(_StubCfg(egress_proxy_url=blank))
```

- [ ] **Step 3: Run the proof test (runtime green) + type-check (intended mixed-red)**

Run: `uv run pytest tests/unit/egress/test_config_protocol_proof.py -v`
Expected: **INTENDED PARTIAL RED (TDD red state).** `test_plain_stub_satisfies_egress_proxy_config`, `test_from_settings_accepts_a_plain_stub`, and `test_from_settings_blank_proxy_fails_closed[None]` PASS; but `test_from_settings_blank_proxy_fails_closed[""]` and `[...whitespace...]` FAIL — because `client.py` still carries the pre-PR `is None` guard, which does NOT reject `""`/whitespace-only. That failure is the point: it proves Task 2's blank-rejection hardening is load-bearing, not cosmetic. Task 2 Step 3 turns all cases green.

Run: `uv run mypy src/alfred/egress/_config_protocols.py tests/unit/egress/test_config_protocol_proof.py`
Expected: **INTENDED RED (this is the TDD red state, not a failure to fix here).** `_settings_satisfies` and `test_plain_stub_satisfies_egress_proxy_config` type-check clean, but the `from_settings`-driving tests (`test_from_settings_accepts_a_plain_stub`, `test_from_settings_blank_proxy_fails_closed`) mypy-error with `Argument 1 to "from_settings" of "EgressClient" has incompatible type "_StubCfg"; expected "Settings"` — because `from_settings` still takes `Settings` until Task 2 narrows it. Do NOT try to clear this red at Task 1; Task 2 Step 3 re-runs both lines and expects full green. (If instead mypy reports `Settings` does not satisfy `EgressProxyConfig` on `_settings_satisfies`, the Protocol shape is wrong — fix the Protocol, not the proof.)

- [ ] **Step 4: Commit**

```bash
git add src/alfred/egress/_config_protocols.py tests/unit/egress/test_config_protocol_proof.py
git commit -m "feat(egress): add EgressProxyConfig read-only Protocol + satisfaction proof (#351)"
```

---

### Task 2: Narrow `EgressClient.from_settings` to `EgressProxyConfig`

**Files:**

- Modify: `src/alfred/egress/client.py` (the `TYPE_CHECKING` import at line 33; the classmethod at lines 42–54)

**Interfaces:**

- Consumes: `EgressProxyConfig` from Task 1.
- Produces: `EgressClient.from_settings(config: EgressProxyConfig) -> EgressClient`. The sole caller (`cli/_bootstrap.py:144`) passes a real `Settings` positionally and is unaffected.

- [ ] **Step 1: Confirm the red state from Task 1**

Run: `uv run mypy src/alfred/egress/client.py tests/unit/egress/test_config_protocol_proof.py`
Expected: FAIL — `Argument 1 to "from_settings" of "EgressClient" has incompatible type "_StubCfg"; expected "Settings"`. This confirms `from_settings` still demands concrete `Settings`.

- [ ] **Step 2: Narrow the param + swap the import**

In `src/alfred/egress/client.py`:

Replace the `TYPE_CHECKING` import (lines 32–33). `EgressProxyConfig` is referenced only in an annotation, so it stays under `TYPE_CHECKING` (with `from __future__ import annotations` the annotation is a string at runtime):

```python
# before:
if TYPE_CHECKING:
    from alfred.config.settings import Settings
# after:
if TYPE_CHECKING:
    from alfred.egress._config_protocols import EgressProxyConfig
```

Re-type `from_settings` (lines 42–54) — rename `settings` → `config`, body/behaviour unchanged:

```python
    @classmethod
    def from_settings(cls, config: EgressProxyConfig) -> EgressClient:
        # Method keeps the ``from_settings`` name (the composition-root factory idiom) while
        # narrowing its param to the read-only EgressProxyConfig Protocol (#351 DIP): the sole
        # prod caller (cli/_bootstrap) still passes a real Settings, which satisfies it.
        #
        # Fail closed on any BLANK proxy URL — None, "", or whitespace-only. A real Settings
        # never yields blank (the mode="before" _normalize_egress_proxy_url collapses
        # blank/whitespace->None), so this is zero-behaviour-change for that caller; but the
        # narrowed param admits an unnormalized value, so the seam self-defends rather than
        # trusting the producer's normalizer — a blank proxy URL must never build a client.
        # G7-3 (ADR-0042): the connectivity-free core has no direct-egress fallback.
        proxy_url = config.egress_proxy_url
        if not (proxy_url and proxy_url.strip()):
            raise IOPlaneUnavailableError(
                detail=(
                    "ALFRED_EGRESS_PROXY_URL is unset or blank — the connectivity-free core "
                    "has no direct-egress fallback; set it to the gateway L7 CONNECT proxy "
                    "(compose default http://alfred-gateway:8889)."
                )
            )
        return cls(proxy_url=proxy_url)
```

(Method name stays `from_settings` — the composition root's factory name; only the param TYPE narrows, with the naming rationale folded into the classmethod comment. Guard fully rejects blank — `None`, `""`, AND whitespace-only — per the security-lens plan review + the PR-review round: the narrowed Protocol drops the normalizer guarantee, so the seam self-defends completely against any blank a stub could supply. A single local `proxy_url` read keeps mypy's non-None narrowing robust across the two accesses. Leave the module docstring's `from_settings` references as-is.)

- [ ] **Step 3: Verify green + no unused import/ignore**

Run: `uv run mypy src/alfred/egress/client.py tests/unit/egress/test_config_protocol_proof.py`
Expected: `Success: no issues found` (the stub now type-checks against the narrowed param).

Run: `uv run pytest tests/unit/egress/test_egress_client.py tests/unit/egress/test_config_protocol_proof.py -v`
Expected: PASS (existing seam tests via real `Settings` + the 3 new proof tests).

Run: `uv run ruff check src/alfred/egress/client.py`
Expected: clean — confirms the swapped import left no `F401` and nothing else in `client.py` references `Settings`.

- [ ] **Step 4: Commit**

```bash
git add src/alfred/egress/client.py
git commit -m "refactor(egress): narrow EgressClient.from_settings to EgressProxyConfig (#351)"
```

---

### Task 3: Full quality gate + open the PR

**Files:** none (verification + PR).

- [ ] **Step 1: Run the full local quality bar**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: clean.

Run: `uv run mypy src/ && uv run pyright src/`
Expected: both clean. `mypy` with `warn_unused_ignores = true` fails if any now-redundant `# type: ignore` remains — remove any it flags (none expected: `client.py` carries no config-related ignore).

Run: `uv run pytest tests/unit/egress tests/unit/config/test_settings_egress_proxy_url.py -q`
Expected: PASS — includes the retained normalizer test (validator-retention evidence) untouched.

- [ ] **Step 2: Run the in-core HTTP-egress import-guard + bootstrap egress path (zero-behaviour-change proof)**

Run: `uv run pytest tests/unit/egress/test_in_core_http_egress_guard.py tests/unit/cli/test_bootstrap_build_router_egress.py -q`
Expected: PASS. The bootstrap test passes a real `Settings` through `build_router` → `EgressClient.from_settings`, proving `Settings` still satisfies the narrowed consumer end-to-end and the fail-closed seam is intact.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin 351-config-dip-egress
gh pr create --base main \
  --title "refactor(egress): config-consumer DIP PR2 — EgressProxyConfig Protocol (#351)" \
  --body "$(cat <<'BODY'
## What
PR2 of the #351 config-consumer DIP pass (design:
docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md; PR1 = memory,
merged 96d13286). Narrows egress/client.py's sole consumer
(EgressClient.from_settings) from the concrete Settings god-object to a narrow
read-only EgressProxyConfig Protocol reading only egress_proxy_url.

## First validator-coupled batch
egress_proxy_url carries a mode="before" normalizer (_normalize_egress_proxy_url,
blank->None). Per the design's validator-coupling rule, the Protocol docstrings the
producer invariant and the existing real-Settings normalizer test
(tests/unit/config/test_settings_egress_proxy_url.py) is retained untouched as the
validator-retention evidence (a plain stub bypasses the normalizer).

## Zero behaviour change
Pure typing/DIP refactor. Settings satisfies EgressProxyConfig structurally (PEP 544),
so the sole caller (cli/_bootstrap.py, composition root) is unchanged; the bootstrap
egress path + import-guard suites pass with a real Settings.

## Follow-ups (later batches, same design)
providers -> plugins/web_fetch -> security -> optional PGH capstone.

https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
BODY
)"
```

- [ ] **Step 4: Run `/review-pr` + CodeRabbit, resolve every thread, then `gh pr merge --rebase`**

Follow the project cadence: full `/review-pr` fleet (security ALWAYS) + CodeRabbit (both), resolve every thread (`required_conversation_resolution` is on), never `--admin`. This touches `src/alfred/egress/**`; include the matching subsystem reviewer (egress lives under the devops/security egress plane — pull `alfred-security-engineer` + `alfred-devops-engineer`, plus `alfred-devex-reviewer` for the from_settings ergonomics).

---

## Self-Review

**Spec coverage (PR2 slice):**

- Narrow `@property` Protocol grouped in `egress/_config_protocols.py` — Task 1. ✓
- Sole leaf consumer narrowed; `Settings` import swapped, param renamed `settings`→`config` — Task 2. ✓
- Mechanism-proof as a committed mypy-checked artifact + a plain-stub DIP-win test that drives the real seam — Task 1. ✓
- Fail-closed guard hardened `is None`→full blank check `not (proxy_url and proxy_url.strip())` (security-lens plan review + PR-review round): rejects the whole blank input-domain (`None`/`""`/whitespace-only) the narrowing admits; zero-behaviour-change for real `Settings`; proof test parametrized over `[None, "", "   "]` — Task 1 Step 2 + Task 2 Step 2. ✓
- Validator-coupling rule honoured: Protocol docstrings the `_normalize_egress_proxy_url` producer invariant; the existing real-`Settings` normalizer test is retained untouched — Global Constraints + Task 3 Step 1. ✓
- `warn_unused_ignores` gate + zero-behaviour-change bootstrap/import-guard proof — Task 3. ✓
- Convention doc: already landed in PR1 — no doc change this batch. ✓

**Placeholder scan:** none — every step shows the actual code/command/expected output.

**Type consistency:** `EgressProxyConfig` name + `egress_proxy_url: str | None` property is identical across Task 1 (definition), Task 2 (consumer), and the proof. `from_settings(config: EgressProxyConfig) -> EgressClient` matches between Task 2's Interfaces block and its code.
