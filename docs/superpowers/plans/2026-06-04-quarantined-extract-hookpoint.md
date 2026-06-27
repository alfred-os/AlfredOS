# `security.quarantined.extract` hookpoint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Trust-boundary work — TDD is HARD here, not advisory.

**Goal:** Register the `security.quarantined.extract` hookpoint per spec §6.5 + §14, wire `QuarantinedExtractor.extract` through the hookpoint dispatch chain (pre/post/error), and ship a system-tier `OutboundDlpExtractSubscriber` that runs `OutboundDlp.scan(result.model_dump())` on the post-stage to close the pattern-matchable exfiltration channel.

**Architecture:** Hookpoint declared at module-init in `alfred.security.quarantine`. `extract` body wrapped in `async with invoking("security.quarantined.extract", inp) as flow:` per the `alfred.memory.episodic.record` precedent. New module `alfred.security._extract_dlp_subscriber` carries the subscriber class + a registration helper. `QuarantinedExtractor.__init__` calls the registration helper so subscriber lifecycle anchors to extractor lifecycle (idempotent registration handles multiple instances). Canonical manifest at `_known_hookpoints.py` extended with the new name.

**Tech Stack:** Python 3.14.5 • existing `alfred.hooks` invoke/dispatch infrastructure • `alfred.security.dlp.OutboundDlp` • Pydantic v2 (`ExtractionResult.model_dump()`) • pytest + the existing `tests/unit/hooks/conftest.py` fixtures.

**Spec anchor:** [`docs/superpowers/specs/2026-06-04-quarantined-extract-hookpoint-design.md`](../specs/2026-06-04-quarantined-extract-hookpoint-design.md) — committed on this branch alongside this plan.

**Depends on:** #151 (merged — `_known_hookpoints.py` manifest is the extension point).
**Blocks:** Nothing in flight.

---

## §1 Goal

After this PR merges:

1. `register_hookpoint("security.quarantined.extract", subscribable_tiers=SYSTEM_OPERATOR_TIERS, refusable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)` runs at `alfred.security.quarantine` module-init time.
2. `QuarantinedExtractor.extract` dispatches via the hookpoint chain (pre/post/error stages via `invoking()`).
3. `OutboundDlpExtractSubscriber` (system-tier, post-only) runs `OutboundDlp.scan(json.dumps(result.model_dump()))` and raises `HookRefusal` on canary trip / DLP-detected secret.
4. `QuarantinedExtractor.__init__(outbound_dlp=...)` registers the subscriber idempotently — subscriber lifecycle is anchored to extractor lifecycle.
5. `security.quarantined.extract` lands in the canonical manifest (`_known_hookpoints.py`); the sync test (#151) catches drift.
6. The existing `quarantine.extract` audit-row family stays unchanged (hookpoint dispatch is additive, not replacing).

100% line + branch coverage on the new subscriber module and the modified `extract` body.

---

## §2 File structure

| File | Status | Responsibility |
| --- | --- | --- |
| `src/alfred/security/quarantine.py` | Modify | Add `declare_hookpoints()` at module bottom; wrap `extract` body in `invoking()`; thread `outbound_dlp` through `__init__` to the subscriber registration helper |
| `src/alfred/security/_extract_dlp_subscriber.py` | Create | `OutboundDlpExtractSubscriber` class + `register_extract_dlp_subscriber()` helper |
| `src/alfred/hooks/_known_hookpoints.py` | Modify | Add `"security.quarantined.extract"` under a new `alfred.security.quarantine` key |
| `tests/unit/hooks/test_hookpoint_security_quarantined_extract.py` | Create | Hookpoint metadata pin (tiers + fail_closed) |
| `tests/unit/security/test_extract_dlp_subscriber.py` | Create | Subscriber unit tests (clean, canary, DLP outage) |
| `tests/unit/security/test_quarantined_extract_dlp_chain.py` | Create | End-to-end DLP-in-chain (with + without subscriber registered) |
| `tests/unit/hooks/test_known_hookpoints_basic.py` | Modify | Add presence assertion for the new hookpoint name |
| `tests/unit/security/test_quarantined_to_structured.py` | Modify | If existing tests construct `QuarantinedExtractor` without `outbound_dlp`, update fixtures to pass a stub `OutboundDlp` |

---

## §3 Definition of Done

- [ ] `uv run pytest tests/unit/hooks/ tests/unit/security/ -q` → green.
- [ ] 100% line + branch on `_extract_dlp_subscriber.py` + the new `extract` body (`fetch_dispatcher.py` precedent).
- [ ] `uv run ruff check . && uv run ruff format --check .` → clean.
- [ ] `uv run mypy src/ && uv run pyright src/` → clean.
- [ ] `make check` → green.
- [ ] Conventional Commits + `#158` in every subject + no `fixup!` markers post-autosquash.
- [ ] User check-in before opening the PR.

---

## §4 Tasks

### Task 1 — Hookpoint registration + manifest entry

**Files**:

- Modify: `src/alfred/security/quarantine.py` (just the `declare_hookpoints()` function + module-bottom call — NOT the `extract` wrap yet).
- Modify: `src/alfred/hooks/_known_hookpoints.py` (extend manifest).
- Create: `tests/unit/hooks/test_hookpoint_security_quarantined_extract.py`.
- Modify: `tests/unit/hooks/test_known_hookpoints_basic.py` (add presence assertion).

- [ ] **Step 1: Write failing tests.**

  `tests/unit/hooks/test_hookpoint_security_quarantined_extract.py`:

  ```python
  """Hookpoint metadata pin for security.quarantined.extract (issue #158)."""

  from __future__ import annotations

  import pytest

  from alfred.hooks import (
      SYSTEM_ONLY_TIERS,
      SYSTEM_OPERATOR_TIERS,
      get_registry,
  )


  def test_hookpoint_registered_at_module_import() -> None:
      """Importing alfred.security.quarantine MUST register the hookpoint
      with the exact spec §6.5 metadata."""
      import alfred.security.quarantine  # noqa: F401 — import for side effect

      meta = get_registry()._hookpoints["security.quarantined.extract"]
      assert meta.subscribable_tiers == SYSTEM_OPERATOR_TIERS
      assert meta.refusable_tiers == SYSTEM_ONLY_TIERS
      assert meta.fail_closed is True
  ```

  Also extend `tests/unit/hooks/test_known_hookpoints_basic.py`:

  ```python
  def test_quarantined_extract_hookpoint_present() -> None:
      """#158 acceptance: the new hookpoint lives in the canonical manifest."""
      flat = all_known_hookpoints()
      assert "security.quarantined.extract" in flat
  ```

- [ ] **Step 2: Run; confirm failure.**

- [ ] **Step 3: Implement.**

  At the bottom of `src/alfred/security/quarantine.py` (after `QuarantinedExtractor` class, near the other module-bottom helpers):

  ```python
  def declare_hookpoints(registry: HookRegistry | None = None) -> None:
      """Register the security.quarantined.extract hookpoint (spec §6.5).

      Idempotent — re-import does not double-register. Matches the pattern
      at alfred.memory.episodic.declare_hookpoints (precedent).
      """
      target = registry if registry is not None else get_registry()
      target.register_hookpoint(
          name="security.quarantined.extract",
          subscribable_tiers=SYSTEM_OPERATOR_TIERS,
          refusable_tiers=SYSTEM_ONLY_TIERS,
          fail_closed=True,
      )


  declare_hookpoints()  # at module bottom — runs at import time
  ```

  Add imports at the top of the file as needed: `from alfred.hooks import HookRegistry, SYSTEM_ONLY_TIERS, SYSTEM_OPERATOR_TIERS, get_register_hookpoints, get_registry` — adapt to what the module already imports.

  In `src/alfred/hooks/_known_hookpoints.py`:

  ```python
  KNOWN_HOOKPOINTS: Final[Mapping[str, tuple[str, ...]]] = {
      # ...existing entries unchanged...
      "alfred.security.quarantine": (
          "security.quarantined.extract",
      ),
  }
  ```

- [ ] **Step 4: Run; confirm green.**

- [ ] **Step 5: Run the sync test from #151:**

  ```bash
  uv run pytest tests/unit/hooks/test_known_hookpoints_sync.py -v
  ```

  Expected: green. The sync test should auto-detect the new hookpoint in both the manifest and the runtime registry.

- [ ] **Step 6: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add src/alfred/security/quarantine.py src/alfred/hooks/_known_hookpoints.py tests/unit/hooks/test_hookpoint_security_quarantined_extract.py tests/unit/hooks/test_known_hookpoints_basic.py
  git commit -m "feat(security): register security.quarantined.extract hookpoint (#158)

  Per slice-3 spec §6.5 + §14. Hookpoint registers at module-init time;
  manifest extension makes the validator (#151) cold-start-aware.
  This commit does NOT yet wire the dispatch chain or DLP subscriber —
  those land in Tasks 2 and 3.

  Refs: #158

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 2 — `OutboundDlpExtractSubscriber`

**Files**:

- Create: `src/alfred/security/_extract_dlp_subscriber.py`
- Create: `tests/unit/security/test_extract_dlp_subscriber.py`

- [ ] **Step 1: Write failing tests.**

  `tests/unit/security/test_extract_dlp_subscriber.py`:

  ```python
  """Unit tests for OutboundDlpExtractSubscriber (issue #158)."""

  from __future__ import annotations

  from unittest.mock import Mock

  import pytest

  from alfred.security._extract_dlp_subscriber import OutboundDlpExtractSubscriber
  # HookRefusal + HookContext shapes — adapt to actual API at landing.


  def _build_ctx(payload: dict) -> "HookContext":
      """Build a minimal HookContext with `input=payload`. Adapt to actual API."""
      ...


  @pytest.mark.asyncio
  async def test_clean_payload_returns_ctx_unchanged() -> None:
      dlp = Mock()
      dlp.scan = Mock(side_effect=lambda x: x)  # passthrough
      sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
      ctx = _build_ctx({"summary": "all clear"})
      out = await sub(ctx)
      assert out is ctx


  @pytest.mark.asyncio
  async def test_canary_in_summary_field_raises_refusal() -> None:
      """A canary-token-bearing summary triggers HookRefusal."""
      from alfred.hooks.errors import HookRefusal
      dlp = Mock()
      # DLP redacts the canary — scan output differs from input.
      dlp.scan = Mock(side_effect=lambda x: x.replace("CANARY-XYZ", "[REDACTED]"))
      sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
      ctx = _build_ctx({"summary": "embedded CANARY-XYZ in text"})
      with pytest.raises(HookRefusal):
          await sub(ctx)


  @pytest.mark.asyncio
  async def test_canary_in_nested_dict_field_raises_refusal() -> None:
      """model_dump() can produce nested dicts; canary in nested field still
      surfaces in the JSON serialisation and trips DLP."""
      from alfred.hooks.errors import HookRefusal
      dlp = Mock()
      dlp.scan = Mock(side_effect=lambda x: x.replace("CANARY-XYZ", "[REDACTED]"))
      sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
      ctx = _build_ctx({"meta": {"reason": "saw CANARY-XYZ"}})
      with pytest.raises(HookRefusal):
          await sub(ctx)


  @pytest.mark.asyncio
  async def test_dlp_outage_propagates_loud() -> None:
      """A crashing OutboundDlp.scan MUST propagate (fail_closed=True at
      hookpoint level treats it as refusal)."""
      dlp = Mock()
      dlp.scan = Mock(side_effect=RuntimeError("DLP broker outage"))
      sub = OutboundDlpExtractSubscriber(outbound_dlp=dlp)
      ctx = _build_ctx({"summary": "clean"})
      with pytest.raises(RuntimeError, match="DLP broker outage"):
          await sub(ctx)
  ```

  Implementer: adapt `_build_ctx` + `HookContext` + `HookRefusal` imports to the actual `src/alfred/hooks/` API.

- [ ] **Step 2: Run; confirm failure.**

- [ ] **Step 3: Implement.**

  Create `src/alfred/security/_extract_dlp_subscriber.py` per spec §2.3. Include the inline residual-risk comment block.

  Implementer note: locate the exact `HookContext` + `HookRefusal` API by reading `src/alfred/hooks/`. The spec's class shape is approximate; adapt to actual API.

- [ ] **Step 4: Run; confirm green.**

- [ ] **Step 5: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add src/alfred/security/_extract_dlp_subscriber.py tests/unit/security/test_extract_dlp_subscriber.py
  git commit -m "feat(security): OutboundDlpExtractSubscriber for security.quarantined.extract post (#158)

  System-tier subscriber on the post-stage of the quarantined-extract
  hookpoint. Runs OutboundDlp.scan(json.dumps(model_dump)) on the
  validated ExtractionResult and raises HookRefusal on canary trip /
  DLP-detected secret.

  Inline documentation of the semantic-exfil residual risk: regex DLP
  catches pattern-matchable secrets (canary tokens, API keys, credit
  card patterns) but not arbitrary paraphrased PII in natural-language
  fields. Closing that channel requires AI-based DLP which is out of
  AlfredOS's current threat model.

  Refs: #158

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 3 — `QuarantinedExtractor.extract` dispatch through hookpoint chain

**Files**:

- Modify: `src/alfred/security/quarantine.py`
- Modify: `tests/unit/security/test_quarantined_to_structured.py` (existing — update fixtures if needed)
- Create: `tests/unit/security/test_quarantined_extract_dlp_chain.py`

- [ ] **Step 1: Write failing tests.**

  `tests/unit/security/test_quarantined_extract_dlp_chain.py`:

  ```python
  """End-to-end: QuarantinedExtractor.extract dispatches through the
  security.quarantined.extract hookpoint chain. The DLP subscriber refuses
  on canary trip (issue #158)."""

  from __future__ import annotations

  from unittest.mock import AsyncMock, Mock

  import pytest

  # imports adapted to actual API
  from alfred.security.quarantine import QuarantinedExtractor


  @pytest.mark.asyncio
  async def test_clean_extract_succeeds_with_dlp_subscriber_registered(
      hook_registry_fixture,
  ) -> None:
      """Happy path: clean model_dump passes the DLP subscriber + extract
      returns the validated result."""
      ...


  @pytest.mark.asyncio
  async def test_extract_with_canary_in_response_is_refused_by_dlp_subscriber(
      hook_registry_fixture,
  ) -> None:
      """The quarantined LLM returns an ExtractionResult whose summary
      contains a canary; post-subscriber raises HookRefusal; extract
      propagates; audit row emitted; validated payload never returns."""
      ...


  @pytest.mark.asyncio
  async def test_extract_constructor_raises_when_dlp_subscriber_denied(
      hook_registry_fixture,
  ) -> None:
      """Fail-loud anchor: ``QuarantinedExtractor.__init__`` is the
      lifecycle anchor for the post-stage DLP subscriber. If
      ``register_extract_dlp_subscriber`` cannot land a subscriber on
      the active registry (capability gate denies the system-tier
      registration, hookpoint unavailable, etc.), construction MUST
      raise so a half-wired extractor — one without an active
      post-stage DLP scan on the security.quarantined.extract chain —
      can never exist. The raise propagates out of ``__init__``; the
      caller observes the registration-denied failure rather than a
      passing clean path. (PRD §7.1, CLAUDE.md hard rule `#7`.)"""
      ...
  ```

  Fill in test bodies with actual fixture wiring — drive `QuarantinedExtractor.extract` end-to-end with mocked plugin transport.

- [ ] **Step 2: Run; confirm failure.**

- [ ] **Step 3: Wrap `extract` body in `invoking()`.**

  In `src/alfred/security/quarantine.py`:
  - Add `outbound_dlp: OutboundDlp` parameter to `QuarantinedExtractor.__init__`.
  - In `__init__`, after storing instance state, call:

    ```python
    from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber
    register_extract_dlp_subscriber(outbound_dlp=outbound_dlp)
    ```

    The helper is idempotent — multiple `QuarantinedExtractor` instances → single subscriber registration.

  - In `extract`, wrap the existing body:

    ```python
    from alfred.hooks import invoking
    
    async with invoking("security.quarantined.extract", inp=...) as flow:
        flow = await flow.pre(
            "security.quarantined.extract",
            subscribable_tiers=SYSTEM_OPERATOR_TIERS,
            refusable_tiers=SYSTEM_ONLY_TIERS,
            fail_closed=True,
        )
        
        # ... existing extract body (schema validation, dispatch, audit) ...
        result = ExtractionResult(...)
        
        flow = await flow.post(
            "security.quarantined.extract",
            subscribable_tiers=SYSTEM_OPERATOR_TIERS,
            refusable_tiers=SYSTEM_ONLY_TIERS,
            fail_closed=True,
            with_input=result.model_dump(),
        )
        
        return result
    ```

  Adapt the exact `invoking()` / `flow.pre` / `flow.post` API to whatever the `alfred.hooks.invoke` module provides — the pattern is documented at `src/alfred/memory/episodic.py:259-300`.

  **Important**: the existing `quarantine.extract` audit-row emission at lines 666, 713, 749 STAYS. The hookpoint dispatch is additive; do not remove the existing audit rows.

  If the existing tests in `test_quarantined_to_structured.py` construct `QuarantinedExtractor` without `outbound_dlp`, update them to pass a stub.

- [ ] **Step 4: Run all quarantine + hook tests.**

  ```bash
  uv run pytest tests/unit/security/ tests/unit/hooks/ -v
  ```

- [ ] **Step 5: Coverage gate.**

  ```bash
  uv run pytest tests/unit/security/ \
    --cov=src/alfred/security/_extract_dlp_subscriber \
    --cov=src/alfred/security/quarantine \
    --cov-branch --cov-fail-under=100
  ```

- [ ] **Step 6: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add src/alfred/security/quarantine.py tests/unit/security/test_quarantined_extract_dlp_chain.py tests/unit/security/test_quarantined_to_structured.py
  git commit -m "feat(security): QuarantinedExtractor.extract dispatches through hookpoint chain (#158)

  Wraps the existing extract body in async with invoking(...) per the
  alfred.memory.episodic.record precedent. Pre/post/error stages run
  through the security.quarantined.extract hookpoint registered in
  Task 1. The post-stage DLP subscriber (Task 2) runs OutboundDlp.scan
  on result.model_dump() and refuses on canary trip — closes the
  pattern-matchable exfiltration channel from spec §6.5 line 476.

  Existing quarantine.extract audit-row emissions stay; hookpoint
  dispatch is additive, not replacing.

  QuarantinedExtractor.__init__ now accepts outbound_dlp and registers
  the subscriber idempotently — subscriber lifecycle is anchored to
  extractor lifecycle.

  Refs: #158

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 4 — Final QA + push + STOP

**Files**: none — gates only.

- [ ] **Step 1: Full quality bar.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run ruff check . && uv run ruff format --check .
  uv run mypy src/ && uv run pyright src/
  uv run pytest tests/unit/security/ tests/unit/hooks/ -v
  make check
  ```

  Expected: all green. Pre-existing ruff S603/S607 in `scripts/check_strict_declarations.py` — ignore.

- [ ] **Step 2: Commit log audit.**

  ```bash
  git log --oneline main..HEAD
  ```

  Verify every commit is Conventional Commits, contains `#158`, no `fixup!` prefixes.

- [ ] **Step 3: Push.**

  ```bash
  git push -u origin issue-158-quarantined-extract-hookpoint
  ```

- [ ] **Step 4: STOP for user check-in.**

  Report: branch pushed, commit list, gate status. Do NOT open the PR autonomously.

---

## §5 Post-PR follow-ups (not in this PR's scope)

- AI-based semantic DLP layer (closes the semantic sub-channel).
- Adversarial corpus tightening: verify `tests/adversarial/prompt_injection/pi_direct_injection_into_extracted_data.yaml` exists; if it does, tighten its assertion to require DLP-subscriber refusal. If it doesn't, file a small adjacent issue to add one.
- Migration of `quarantine.extract` audit-row family into the hookpoint dispatch chain's audit (ADR-shaped — conflates two concerns).
