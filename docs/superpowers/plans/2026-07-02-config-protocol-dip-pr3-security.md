# Config-consumer DIP — PR3 (security) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Narrow the `security/capability_gate/_comms_adapter_grants.py` config consumer (`comms_adapter_load_grants`) from the concrete `Settings` god-object to a narrow read-only `CommsAdapterGrantsConfig` Protocol reading only `comms_enabled_adapters`. Second **validator-coupled** batch, and the first in the **highest-care security subsystem** (adversarial suite is release-blocking for any `src/alfred/security/` change).

**Scope note (landscape re-verified 2026-07-02):** the memory inventory listed two security consumers, but `SecretBroker.from_settings` reads a **phantom** `Settings.secrets_file` field that has never existed (issue #363) — it is NOT a valid narrowing target and is EXCLUDED from this PR. `providers` was also found to be a no-op (already primitives). So this batch narrows exactly ONE consumer.

**Architecture:** Add `src/alfred/security/_config_protocols.py` with a single `@property`-based read-only `Protocol` (`CommsAdapterGrantsConfig`) exposing only `comms_enabled_adapters: tuple[str, ...]`. Re-type `comms_adapter_load_grants`'s parameter to consume it (rename `settings` → `config`; free function). Real `Settings` satisfies the Protocol structurally (PEP 544), so the sole caller (`cli/daemon/_commands.py`, composition root — daemon boot) is unchanged and there is **zero runtime behaviour change**. A committed mypy-checked identity-return function proves `Settings` satisfies the Protocol; a stub-based unit test proves the DIP win. The `docs/python-conventions.md` convention already landed in PR1.

**Tech Stack:** Python 3.12+, Pydantic v2, `typing.Protocol`, pytest, mypy `--strict`, pyright, ruff.

## Global Constraints

- **Design source of truth:** `docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md` (#351). PR1 (memory) + PR2 (egress) merged; convention in `docs/python-conventions.md`.
- **Zero runtime behaviour change.** Pure typing/DIP refactor. Existing tests pass unchanged.
- **`Settings` is not modified.** It stays a `BaseSettings`; it only *satisfies* the new Protocol.
- **Boundary:** only the leaf consumer `comms_adapter_load_grants` narrows; the composition root (`cli/daemon/_commands.py:1687`, `cli/_bootstrap.py`, `bootstrap/`, loader, `Settings` def) keeps concrete `Settings`.
- **Validator-coupling rule (this batch — SECURITY-critical).** `comms_enabled_adapters` (settings.py:167, `tuple[str, ...]`, default `()`) has a `_validate_comms_enabled_adapters` field validator (settings.py:305) that proves each entry is charset-safe, NOT a `.`/`..` traversal probe, path-CONTAINED under `plugins/`, AND names a real `plugins/<id>/manifest.toml`. The builder (`_comms_adapter_grants.py`) turns each id into a filesystem path and `read_text()`s it, so this validator is a **path-traversal / arbitrary-manifest-read defense**.
- **DECISION — do NOT self-defend by duplicating the validator (contrast with PR2/egress). CONFIRMED by the security-lens plan review (verdict: sound, no blocker).** PR2 hardened its guard because the normalizer was a trivial blank→None transform cheaply mirror-able inline. Here the validator is a multi-check security validator; re-implementing charset/traversal/containment/exists checks inside the builder would DRY-violate a security validator and risk the two drifting. The security review's load-bearing rebuttal to the "widened domain" worry: typing the param `Settings` **never implied "validated"** (`Settings.model_construct(comms_enabled_adapters=("../../etc",))` already bypasses every validator today), so the narrowing removes no guarantee that actually existed — the validation guarantee lives at the **construction site** (the composition root builds a validated `Settings`), which this PR does not touch. The posited "stub with a traversal id" attack requires developer-authored code and is outside the external-content threat model. Instead of self-defending: (a) **retain `tests/unit/security/capability_gate/test_comms_adapter_grants.py` UNTOUCHED** — it constructs real (validated) `Settings` via `_settings_with_adapters(...)` and drives the builder; it is the real-`Settings` validator-retention evidence per the design rule. The validator's traversal/charset/exists REJECTION assertions live in `tests/unit/config/test_settings_comms_enabled_adapters.py` (also untouched) — cite that as the rejection-coverage home. (b) **Strongly docstring the producer invariant** on `CommsAdapterGrantsConfig` (incl. the "enforced at construction, not by the type" clause). (c) The builder ALREADY fails loud on a missing/unreadable manifest (`read_text` raises, unguarded, surfaced — never a silent skip; the manifest content never returns to a caller/log). **Optional sink-local containment hardening (security review R1) is deliberately OUT OF SCOPE** — it is pre-existing (not a regression from this zero-behaviour-change refactor) and tracked as its own follow-up; do NOT copy the validator into the builder.
- **Highest-care subsystem gates:** any change under `src/alfred/security/**` REQUIRES the full adversarial suite locally (`uv run pytest tests/adversarial`, release-blocking) + the `alfred-security-engineer` reviewer (always-on in `/review-pr`). The `_comms_adapter_grants.py` module carries a per-file 100% line+branch coverage gate (named in ci.yml) — coverage must not drop.
- **Read-only intent via `@property`** getters; satisfied by `Settings`' attribute and a plain stub.
- **Sole consumer / sole caller.** `grep comms_enabled_adapters src/alfred/` → settings.py (field + validator), `_comms_adapter_grants.py` (the consumer). `grep comms_adapter_load_grants src/alfred/` (callers) → only `cli/daemon/_commands.py:1687` (positional `comms_adapter_load_grants(settings)`). No keyword-arg `settings=` caller, so the param rename is safe.
- **Modern typing:** PEP 604/585; `from __future__ import annotations` at file top.
- **Commit trailer (every commit):**

  ```
  MrReasonable <4990954+MrReasonable@users.noreply.github.com>
  Claude-Session: https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
  ```

- **Conventional Commits** with a literal `#351` in every commit subject.
- **Branch:** `351-config-dip-security` (already checked out off `origin/main`).

---

## File Structure

- `src/alfred/security/_config_protocols.py` — **Create.** Holds `CommsAdapterGrantsConfig` (the security subsystem's narrow config Protocols module; subsystem-level per convention, mirroring `memory/`+`egress/_config_protocols.py`). *(Architect plan-review confirmed subsystem-level over a `capability_gate/`-local file: coverage is neutral, and this is the natural home for a future second security config Protocol once #363 resolves the SecretBroker phantom field.)* Use the SAME single-line getter form as egress (`def x(self) -> T: ...`) so the getter line is import-covered under the `security/*` 100% gate (see Task 3 Step 2).
- `src/alfred/security/capability_gate/_comms_adapter_grants.py` — **Modify.** Re-type `comms_adapter_load_grants`'s param (`settings: Settings` → `config: CommsAdapterGrantsConfig`), swap the `TYPE_CHECKING` `Settings` import, `s/settings/config/` in the body + docstring prose.
- `tests/unit/security/capability_gate/test_config_protocol_proof.py` — **Create.** The mechanism-proof (`Settings` satisfies) + a plain-stub DIP-win test that drives `comms_adapter_load_grants` against a trivial double.
- `tests/unit/security/capability_gate/test_comms_adapter_grants.py` — **Untouched (retained).** Real-`Settings` validator-retention evidence; do NOT edit.

---

### Task 1: `CommsAdapterGrantsConfig` Protocol + the structural-satisfaction proof

**Files:**

- Create: `src/alfred/security/_config_protocols.py`
- Create: `tests/unit/security/capability_gate/test_config_protocol_proof.py`

**Interfaces:**

- Produces: `alfred.security._config_protocols.CommsAdapterGrantsConfig` — a `Protocol` with a read-only `comms_enabled_adapters: tuple[str, ...]` property. Consumed by Task 2 and the proof test.

- [ ] **Step 1: Write the Protocol module**

Create `src/alfred/security/_config_protocols.py`:

```python
"""Narrow read-only config Protocols for the security subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol


class CommsAdapterGrantsConfig(Protocol):
    """The config surface ``comms_adapter_load_grants`` reads: the enabled comms adapters.

    Producer invariant (SECURITY-critical): ``Settings.comms_enabled_adapters`` is
    validated by ``_validate_comms_enabled_adapters`` (settings.py) — every id is
    charset-checked, rejected if it is a ``.``/``..`` traversal probe, proven CONTAINED
    under ``plugins/``, and proven to name a real ``plugins/<id>/manifest.toml``. The
    builder turns each id into a filesystem path and reads it, so callers MUST supply a
    value that has passed that validator (a plain stub bypasses it). The builder does NOT
    re-validate — it relies on this construction-time proof (ADR-0027 config-is-authorization)
    and fails LOUD on any manifest it cannot read (never a silent skip). Passing an
    unvalidated stub with a traversal-shaped id is a caller error, not a builder concern.

    NOTE: this guarantee is enforced at the ``Settings`` CONSTRUCTION site (the composition
    root builds a validated ``Settings``), NOT by this Protocol or by the ``tuple[str, ...]``
    type — a ``Settings.model_construct(...)`` or a raw stub bypasses the validator entirely.
    A future second consumer of this Protocol inherits NO validation from the type.
    """

    @property
    def comms_enabled_adapters(self) -> tuple[str, ...]: ...
```

- [ ] **Step 2: Write the proof + stub DIP-win test**

Create `tests/unit/security/capability_gate/test_config_protocol_proof.py`:

```python
"""Structural-satisfaction proof for the security config Protocol (#351).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> CommsAdapterGrantsConfig`` iff ``Settings`` satisfies the
Protocol, so a real ``Settings`` can be passed wherever ``CommsAdapterGrantsConfig`` is
required — and a future ``Settings.comms_enabled_adapters`` rename fails the type-check
instead of silently drifting. The stub test proves the DIP win: the builder works against
a trivial double, not just a full ``Settings``.

Validator-coupling note (#351): the SECURITY invariant that each enabled adapter id is
charset/traversal/containment/manifest-exists checked lives in
``_validate_comms_enabled_adapters`` and is covered by the retained real-``Settings`` test
``test_comms_adapter_grants.py``. This proof deliberately uses only the default-empty
adapter set so it exercises the DIP seam WITHOUT depending on / re-testing the validator.
"""

from __future__ import annotations

from alfred.config.settings import Settings
from alfred.security._config_protocols import CommsAdapterGrantsConfig
from alfred.security.capability_gate._comms_adapter_grants import comms_adapter_load_grants


def _settings_satisfies(settings: Settings) -> CommsAdapterGrantsConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


class _StubCfg:
    """A trivial config double — NOT a Settings — supplying the one field the builder reads."""

    def __init__(self, *, comms_enabled_adapters: tuple[str, ...]) -> None:
        self.comms_enabled_adapters = comms_enabled_adapters


def test_plain_stub_satisfies_comms_adapter_grants_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""
    cfg: CommsAdapterGrantsConfig = _StubCfg(comms_enabled_adapters=())
    assert cfg.comms_enabled_adapters == ()


def test_comms_adapter_load_grants_accepts_a_plain_stub() -> None:
    """comms_adapter_load_grants consumes CommsAdapterGrantsConfig — a stub drives the seam.

    Uses the default-empty adapter set: the builder returns () without reading any manifest,
    proving the seam consumes the narrow Protocol without depending on the validator surface.
    """
    assert comms_adapter_load_grants(_StubCfg(comms_enabled_adapters=())) == ()
```

- [ ] **Step 3: Run the proof test + type-check (intended mixed-red)**

Run: `uv run pytest tests/unit/security/capability_gate/test_config_protocol_proof.py -v`
Expected: PASS (2 tests — Python is duck-typed, so the stub-driven test passes at runtime even while mypy is red below).

Run: `uv run mypy src/alfred/security/_config_protocols.py tests/unit/security/capability_gate/test_config_protocol_proof.py`
Expected: **INTENDED RED.** `_settings_satisfies` + `test_plain_stub_...` type-check clean, but `test_comms_adapter_load_grants_accepts_a_plain_stub` mypy-errors (`Argument 1 to "comms_adapter_load_grants" has incompatible type "_StubCfg"; expected "Settings"`) because the builder still takes `Settings` until Task 2 narrows it. Do NOT clear this red at Task 1; Task 2 re-runs and expects green. (If mypy instead reports `Settings` does not satisfy `CommsAdapterGrantsConfig` on `_settings_satisfies`, the Protocol shape is wrong — fix the Protocol, not the proof.)

- [ ] **Step 4: Commit**

```bash
git add src/alfred/security/_config_protocols.py tests/unit/security/capability_gate/test_config_protocol_proof.py
git commit -m "feat(security): add CommsAdapterGrantsConfig read-only Protocol + satisfaction proof (#351)"
```

---

### Task 2: Narrow `comms_adapter_load_grants` to `CommsAdapterGrantsConfig`

**Files:**

- Modify: `src/alfred/security/capability_gate/_comms_adapter_grants.py` (the `TYPE_CHECKING` import at line 70; the function at line 97; the body read at line 129)

**Interfaces:**

- Consumes: `CommsAdapterGrantsConfig` from Task 1.
- Produces: `comms_adapter_load_grants(config: CommsAdapterGrantsConfig) -> tuple[GrantRow, ...]`. The sole caller (`cli/daemon/_commands.py:1687`) passes a real `Settings` positionally and is unaffected.

- [ ] **Step 1: Confirm the red state from Task 1**

Run: `uv run mypy src/alfred/security/capability_gate/_comms_adapter_grants.py tests/unit/security/capability_gate/test_config_protocol_proof.py`
Expected: FAIL — `Argument 1 to "comms_adapter_load_grants" has incompatible type "_StubCfg"; expected "Settings"`.

- [ ] **Step 2: Narrow the param + swap the import**

In `src/alfred/security/capability_gate/_comms_adapter_grants.py`:

Replace the `TYPE_CHECKING` import (line 69-70):

```python
# before:
if TYPE_CHECKING:
    from alfred.config.settings import Settings
# after:
if TYPE_CHECKING:
    from alfred.security._config_protocols import CommsAdapterGrantsConfig
```

Re-type `comms_adapter_load_grants` (line 97) — rename `settings` → `config`, body/behaviour unchanged. Update the signature line and the `for adapter_id in settings.comms_enabled_adapters:` (line 129) → `config.comms_enabled_adapters`. Update the docstring's `Pure ``Settings -> tuple[GrantRow, ...]`` transform` prose to `Pure ``CommsAdapterGrantsConfig -> tuple[GrantRow, ...]`` transform` and keep the "the Settings validator proved the file existed" comment (it correctly refers to the producer invariant — see the Protocol docstring).

```python
def comms_adapter_load_grants(config: CommsAdapterGrantsConfig) -> tuple[GrantRow, ...]:
    ...
    for adapter_id in config.comms_enabled_adapters:
        ...
```

(Free function — no method-name question. Only the param TYPE narrows + the `settings`→`config` rename. Do NOT add any re-validation of `adapter_id` — the builder relies on the construction-time validator per the Global Constraints decision; keep the loud `read_text` failure path exactly as-is.)

- [ ] **Step 3: Verify green + no unused import**

Run: `uv run mypy src/alfred/security/capability_gate/_comms_adapter_grants.py tests/unit/security/capability_gate/test_config_protocol_proof.py`
Expected: `Success: no issues found`.

Run: `uv run pytest tests/unit/security/capability_gate/ -v`
Expected: PASS (the retained `test_comms_adapter_grants.py` real-`Settings` suite + the 2 new proof tests).

Run: `uv run ruff check src/alfred/security/capability_gate/_comms_adapter_grants.py`
Expected: clean — confirms the swapped import left no `F401` and nothing else references `Settings` in the file.

- [ ] **Step 4: Commit**

```bash
git add src/alfred/security/capability_gate/_comms_adapter_grants.py
git commit -m "refactor(security): narrow comms_adapter_load_grants to CommsAdapterGrantsConfig (#351)"
```

---

### Task 3: Full quality gate (incl. the release-blocking adversarial suite) + open the PR

**Files:** none (verification + PR).

- [ ] **Step 1: Run the full local quality bar**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: clean.

Run: `uv run mypy src/ && uv run pyright src/`
Expected: both clean. `warn_unused_ignores` fails on any now-redundant `# type: ignore` — none expected.

Run: `uv run pytest tests/unit/security -q`
Expected: PASS — includes the retained validator test untouched + the new proof tests.

- [ ] **Step 2: Verify the `security/*` 100% coverage gate (architect plan-review B1 — this subsystem has a gate egress/memory did not)**

The new `src/alfred/security/_config_protocols.py` falls under the `ci.yml` gate `coverage report --include='src/alfred/security/*' --fail-under=100`. A `Protocol` `@property` getter body is never executed, so this MUST be verified (not assumed):

Run:
```bash
uv run pytest tests/unit -q --cov=src/alfred --cov-report= && \
uv run coverage report --include='src/alfred/security/*' --fail-under=100
```
Expected: `--fail-under=100` PASSES. The single-line getter form `def comms_enabled_adapters(self) -> tuple[str, ...]: ...` executes its whole line at import (the proof test imports the module), so it should report 100%. If — and ONLY if — it red-lines on the Protocol module's `...` line, add the surgical exclusion to `pyproject.toml [tool.coverage.report]`:
```toml
exclude_also = ["\\.\\.\\."]
```
Do NOT pre-emptively add the exclusion — run the gate first; only add it if the report shows the `...` line uncovered. Re-run the gate after any change.

- [ ] **Step 3: Run the RELEASE-BLOCKING adversarial suite (mandatory — security subsystem changed)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS. Pay attention to `tests/adversarial/capability_bypass/` (`cap_2026_003` non-enabled-adapter-load-denied, `cap_2026_004` system-tier-comms-adapter-refused) which exercise `comms_adapter_load_grants`. This is a HARD gate: a security-subsystem change may not merge without a green adversarial run. If any adversarial test is flaky on this host, re-run in isolation and rely on CI's adversarial lane; a genuine failure BLOCKS.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin 351-config-dip-security
gh pr create --base main \
  --title "refactor(security): config-consumer DIP PR3 — CommsAdapterGrantsConfig Protocol (#351)" \
  --body "$(cat <<'BODY'
## What
PR3 of the #351 config-consumer DIP pass (design:
docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md; PR1=memory,
PR2=egress, both merged). Narrows the sole live security consumer
(comms_adapter_load_grants) from the concrete Settings god-object to a narrow
read-only CommsAdapterGrantsConfig Protocol reading only comms_enabled_adapters.

## Landscape note
The planned providers batch is a no-op (already primitives). The planned
SecretBroker.from_settings consumer reads a phantom Settings.secrets_file field that
never existed (issue #363) — it is NOT narrowable and is excluded. So this batch is
one consumer.

## Validator-coupled — SECURITY-critical
comms_enabled_adapters carries _validate_comms_enabled_adapters (charset / traversal /
containment / manifest-exists). The builder turns each id into a filesystem path, so
that validator is a path-traversal defense. Per the design's validator-coupling rule we
DO NOT duplicate the validator in the builder (contrast PR2/egress, whose normalizer was
a trivial inline mirror) — a multi-check security validator must not be re-implemented +
risk drifting. Instead: the existing real-Settings test (test_comms_adapter_grants.py) is
retained untouched as the validator-retention evidence, and the Protocol docstrings the
producer invariant. The builder already fails LOUD on any unreadable manifest.

## Zero behaviour change
Settings satisfies CommsAdapterGrantsConfig structurally (PEP 544); the sole caller
(cli/daemon/_commands.py, composition root — daemon boot) is unchanged.

## Gates
- ruff / mypy src (warn_unused_ignores) / pyright src: clean
- tests/unit/security + the retained validator test: pass
- tests/adversarial (release-blocking; capability_bypass cap_2026_003/004 exercise this
  builder): pass

## Follow-ups
web_fetch batch (egress_relay_url; maybe-unwired, pending decision). #363 (SecretBroker
phantom field). providers batch closed as a no-op.

https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
BODY
)"
```

- [ ] **Step 5: Run `/review-pr` + CodeRabbit, resolve every thread, then `gh pr merge --rebase`**

Full `/review-pr` fleet (security ALWAYS — and it is the load-bearing lens here) + CodeRabbit (both), resolve every thread (`required_conversation_resolution` is on), never `--admin`. Because this touches `src/alfred/security/**`, the `alfred-security-engineer` reviewer is auto-included and its verdict on the "don't self-defend / rely on the retained validator test" decision is the gate.

---

## Self-Review

**Spec coverage (PR3 slice):**

- Narrow `@property` Protocol grouped in `security/_config_protocols.py` — Task 1. ✓
- Sole leaf consumer narrowed; `Settings` import swapped, param renamed `settings`→`config` — Task 2. ✓
- Mechanism-proof (mypy-checked `_settings_satisfies`) + a plain-stub DIP-win test that drives the real builder on the default-empty set (no validator dependency) — Task 1. ✓
- Validator-coupling honoured WITHOUT duplicating a security validator: retained real-`Settings` test untouched + Protocol docstrings the traversal/containment/exists invariant; builder still fails loud — Global Constraints + Task 2. ✓ (Security-lens plan review confirms this before impl.)
- Adversarial suite run as a release-blocking gate for the security-subsystem change — Task 3 Step 2. ✓
- Convention doc: already landed in PR1 — no doc change. ✓

**Placeholder scan:** none — every step shows the actual code/command/expected output.

**Type consistency:** `CommsAdapterGrantsConfig` name + `comms_enabled_adapters: tuple[str, ...]` property identical across Task 1 (definition), Task 2 (consumer), and the proof.
