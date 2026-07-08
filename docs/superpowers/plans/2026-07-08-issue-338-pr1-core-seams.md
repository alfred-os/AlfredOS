# #338 PR1 — Core seams for the real-turn graduation (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the three behaviour-neutral seams the #338 daemon cutover (PR2) needs — an optional `egress_context` on the privileged turn, `display_name` on the resolved inbound identity, and a dependency-injectable `build_orchestrator` — with no live caller, so `main` stays coherent (the daemon still runs the echo adapter).

**Architecture:** Additive-only changes to three isolated seams. (1) `Orchestrator.handle_user_message`/`_handle_turn` gain an optional `egress_context: TurnEgressContext | None = None`, consumed at the single synthesis site (`core.py:762`) with a fallback to the existing `_synthesize_egress_context` — existing callers pass nothing and are byte-for-byte unchanged. (2) `ResolvedInbound` gains a `display_name` field, populated by the identity bridge and threaded into the inbound `ingest(...)` call (the echo adapter ignores unknown kwargs, so this is inert today). (3) `build_orchestrator` gains optional pre-built `broker`/`router`/`resolver`/`session_scope` params that default to building — so PR2's daemon boot graph can reuse its already-built components instead of double-building the broker and re-firing the process-global `install_identity_factories_for_settings`.

**Tech Stack:** Python 3.14+, asyncio, Pydantic v2, pytest, `mypy --strict` + `pyright`, `ruff`, frozen dataclasses. Package manager: `uv`.

## Global Constraints

- **Behaviour-neutral, no live caller.** PR1 adds NO production consumer of any seam; the daemon boot path is untouched and still constructs the echo `CommsInboundOrchestratorAdapter`. `main` stays green + coherent (seam-first precedent: #339 PR1, G7-2a).
- **Out of scope (PR2 / follow-ups):** the `RealTurnOrchestratorAdapter`, the `_build_comms_boot_graph` swap, the `IOPlaneUnavailableError`/`UnknownSecretError` refuse-boot arms, the tool registry / egress / journal / temp=0 work. Do NOT touch `src/alfred/security/`, the daemon boot graph, or any tool/egress path.
- **TDD-first.** Every change lands failing-test-first (write test → run-fail → implement → run-pass → commit).
- **Typing.** `mypy --strict` + `pyright` clean. PEP 604 unions, no `Any` without justification, frozen/immutable by default.
- **Conventional Commits with a literal `#338` AFTER the colon in EVERY commit subject** (a `(scope)` does not satisfy the `pr-validate-commits` gate). Commit `type` is lowercase letters only (no digits) — use `feat`/`refactor`/`test`/`chore`.
- **`make check` before every push** (`uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` + unit + integration). Check the real exit code — `| tail` masks it.
- **No `--no-verify`; no pre-commit hook skipping.**
- PR1 does not touch `src/alfred/security/`, so the adversarial suite is NOT release-blocking for this PR (still run `make check`).

## Subsystem coverage matrix

| Subsystem | Files | Owner agent |
| --- | --- | --- |
| Orchestrator core (OODA turn, `build_orchestrator`) | `src/alfred/orchestrator/core.py`, `src/alfred/cli/_bootstrap.py` | `alfred-core-engineer` |
| Comms inbound identity | `src/alfred/comms_mcp/inbound.py`, `src/alfred/comms_mcp/bootstrap.py` | `alfred-comms-engineer` |

Plan-level owner: `alfred-core-engineer`. Conditional reviewers for `/review-plan`: core, comms, plus the always-include architect / reviewer / test / security.

## File structure

- `src/alfred/orchestrator/core.py` — add `egress_context` param to `handle_user_message` (`:379`) + `_handle_turn` (`:668`); consume it at the synthesis site (`:762`). No new file.
- `src/alfred/comms_mcp/inbound.py` — add `display_name: str` to `ResolvedInbound` (`:83-99`); thread `display_name=resolved.display_name` into the `orchestrator.ingest(...)` call (`:872-878`).
- `src/alfred/comms_mcp/bootstrap.py` — `SyncIdentityResolverBridge.resolve` (`:180-204`) sets `display_name=user.display_name`.
- `src/alfred/cli/_bootstrap.py` — `build_orchestrator` (`:459-508`) gains optional pre-built component params.
- Tests: `tests/unit/orchestrator/test_act_loop.py` (egress_context selection), `tests/unit/comms_mcp/test_bootstrap.py` (bridge display_name — create if absent), `tests/integration/test_orchestrator_bootstrap.py` (build_orchestrator DI), plus updating the 4 non-production `ResolvedInbound(...)` constructor call-sites.

---

### Task 1: Optional `egress_context` on the privileged turn

**Files:**

- Modify: `src/alfred/orchestrator/core.py:379-438` (`handle_user_message`), `:668-676` (`_handle_turn` signature), `:762` (synthesis site)
- Test: `tests/unit/orchestrator/test_act_loop.py`

**Interfaces:**

- Consumes: `TurnEgressContext` (already imported at `core.py:96`); `DeadlineWrapper.run` forwards arbitrary `**kwargs` to `fn`, stripping only `_user_id`/`_correlation_id` (`supervisor/deadline.py:70`).
- Produces: `handle_user_message(*, user, content, working_memory, egress_context: TurnEgressContext | None = None) -> str` — PR2's adapter passes the real `TurnEgressContext`; every other caller omits it and gets the unchanged synthesis behaviour.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/orchestrator/test_act_loop.py`; reuse the module's existing `_make_orchestrator`, `_stub_user`, `_tag_t2`, `_make_working_memory`, `_make_no_op_budget`, `_text_response` helpers and the `TurnEgressContext` import at line 12):

```python
async def test_handle_user_message_uses_provided_egress_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provided egress_context short-circuits the per-turn synthesis."""
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("ok"))
    orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
    spy = MagicMock(wraps=orch._synthesize_egress_context)
    monkeypatch.setattr(orch, "_synthesize_egress_context", spy)
    provided = TurnEgressContext(
        adapter_id="discord", inbound_id="ib-1", session_id="alice-slug"
    )
    await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2("hello"),
        working_memory=_make_working_memory(),
        egress_context=provided,
    )
    spy.assert_not_called()


async def test_handle_user_message_synthesizes_when_no_egress_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no egress_context (the default), the turn synthesizes as before."""
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("ok"))
    orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
    spy = MagicMock(wraps=orch._synthesize_egress_context)
    monkeypatch.setattr(orch, "_synthesize_egress_context", spy)
    await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2("hello"),
        working_memory=_make_working_memory(),
    )
    spy.assert_called_once()
```

Ensure `import pytest` and `from unittest.mock import AsyncMock, MagicMock` are present at the top of the file (they are used by the existing tests).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py::test_handle_user_message_uses_provided_egress_context tests/unit/orchestrator/test_act_loop.py::test_handle_user_message_synthesizes_when_no_egress_context -v`
Expected: FAIL — `handle_user_message()` got an unexpected keyword argument `egress_context`.

- [ ] **Step 3: Add the param and thread it through**

In `handle_user_message` (`core.py:379`) add the parameter:

```python
    async def handle_user_message(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        egress_context: TurnEgressContext | None = None,
    ) -> str:
```

In the `_deadline_wrapper.run(...)` call (`core.py:429-438`) forward it (the wrapper strips `_user_id`/`_correlation_id` and forwards the rest):

```python
                reply = await self._deadline_wrapper.run(
                    self._handle_turn,
                    session,
                    user=user,
                    content=content,
                    working_memory=working_memory,
                    trace_id=trace_id,
                    egress_context=egress_context,
                    _user_id=user.slug,
                    _correlation_id=trace_id,
                )
```

In `_handle_turn` (`core.py:668`) add the parameter:

```python
    async def _handle_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        trace_id: str,
        egress_context: TurnEgressContext | None = None,
    ) -> str:
```

At the synthesis site (`core.py:762`) select provided-over-synthesized:

```python
        ctx = (
            egress_context
            if egress_context is not None
            else self._synthesize_egress_context(trace_id=trace_id, user=user)
        )
```

Add a one-line docstring note under `handle_user_message`'s Args (WHY, non-obvious): `egress_context` — when the live comms inbound path supplies the real `(adapter_id, inbound_id, session_id)` identity; `None` (the default) synthesizes it deterministically from the turn `trace_id` for the `alfred chat`/fixture path (#338).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v`
Expected: PASS (the two new tests + the existing suite, including `test_synthesize_egress_context_is_deterministic_for_the_turn`).

- [ ] **Step 5: Type-check the change**

Run: `uv run mypy src/alfred/orchestrator/core.py && uv run pyright src/alfred/orchestrator/core.py`
Expected: no new errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/orchestrator/core.py tests/unit/orchestrator/test_act_loop.py
git commit -m "feat(orchestrator): thread optional egress_context through the turn #338"
```

---

### Task 2: `display_name` on `ResolvedInbound`

**Files:**

- Modify: `src/alfred/comms_mcp/inbound.py:83-99` (`ResolvedInbound`), `:872-878` (the `ingest(...)` call)
- Modify: `src/alfred/comms_mcp/bootstrap.py:180-204` (`SyncIdentityResolverBridge.resolve`)
- Update constructors: `tests/unit/comms_mcp/_inbound_spies.py`, `tests/integration/test_discord_subpayload_promotion.py`, `tests/integration/test_discord_addressing_modes.py`, `tests/integration/test_tui_round_trip.py`
- Test: `tests/unit/comms_mcp/test_bootstrap.py` (create if absent)

**Interfaces:**

- Consumes: the sync `IdentityResolver` returns a `User` with `.slug`, `.display_name`, `.language` (`identity/resolver.py:144`, `.display_name` at `:262`).
- Produces: `ResolvedInbound(canonical_user_id, persona, language, adapter_id, display_name)` — PR2's adapter reads `display_name` to build the turn's `UserLike`. The inbound `ingest(...)` call forwards `display_name=resolved.display_name`; the echo adapter's `ingest(self, **kwargs)` ignores it (inert today).

- [ ] **Step 1: Write the failing test** (`tests/unit/comms_mcp/test_bootstrap.py` — create if it does not exist; if it exists, append):

```python
"""Unit tests for the comms-MCP host bootstrap bridges (#338 PR1)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from alfred.comms_mcp.bootstrap import SyncIdentityResolverBridge


@pytest.mark.asyncio
async def test_resolver_bridge_carries_display_name() -> None:
    """The bridge copies the resolved User's display_name onto ResolvedInbound."""
    user = MagicMock()
    user.slug = "alice-slug"
    user.display_name = "Alice"
    user.language = "en"
    resolver = MagicMock()
    resolver.resolve.return_value = user
    bridge = SyncIdentityResolverBridge(resolver=resolver)

    resolved = await bridge.resolve(adapter_id="tui", platform_user_id="u-1")

    assert resolved is not None
    assert resolved.display_name == "Alice"
    assert resolved.canonical_user_id == "alice-slug"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_bootstrap.py::test_resolver_bridge_carries_display_name -v`
Expected: FAIL — `ResolvedInbound` has no attribute/field `display_name` (or a `TypeError` on the missing keyword).

- [ ] **Step 3: Add the field + populate it + thread it**

In `ResolvedInbound` (`inbound.py:83-99`) add the field (required — no silent-empty; frozen/slots dataclass):

```python
    canonical_user_id: str
    persona: str
    language: str
    adapter_id: str
    display_name: str
```

Update the docstring's "Carries exactly what the downstream steps need" list to include "the user's display name".

In `SyncIdentityResolverBridge.resolve` (`bootstrap.py:199-204`) set it:

```python
        return ResolvedInbound(
            canonical_user_id=user.slug,
            persona=_DEFAULT_PERSONA,
            language=user.language,
            adapter_id=adapter_id,
            display_name=user.display_name,
        )
```

In `process_inbound_message`'s `ingest(...)` call (`inbound.py:872-878`) forward it (echo adapter ignores unknown kwargs — behaviour-neutral):

```python
    ingested = await orchestrator.ingest(
        notification=notification,
        extracted=extracted,
        canonical_user_id=resolved.canonical_user_id,
        addressing_signal=notification.addressing_signal,
        language=resolved.language,
        display_name=resolved.display_name,
    )
```

- [ ] **Step 4: Update the 4 non-production `ResolvedInbound(...)` constructors**

Run: `grep -rn "ResolvedInbound(" tests/` and add `display_name="..."` (any non-empty test name, e.g. `display_name="Test User"`) to each of the 4 call-sites (`tests/unit/comms_mcp/_inbound_spies.py`, `tests/integration/test_discord_subpayload_promotion.py`, `tests/integration/test_discord_addressing_modes.py`, `tests/integration/test_tui_round_trip.py`). These are mechanical — a missing keyword will otherwise fail at collection.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/comms_mcp/test_bootstrap.py tests/unit/comms_mcp -v`
Expected: PASS. Then run the touched integration constructors' modules to confirm no collection error: `uv run pytest tests/integration/test_tui_round_trip.py -q` (requires Docker/testcontainers; if unavailable locally, rely on CI — but at minimum `uv run python -c "import tests.integration.test_tui_round_trip"` must import clean).

- [ ] **Step 6: Type-check**

Run: `uv run mypy src/alfred/comms_mcp/inbound.py src/alfred/comms_mcp/bootstrap.py && uv run pyright src/alfred/comms_mcp/inbound.py src/alfred/comms_mcp/bootstrap.py`
Expected: no new errors.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/comms_mcp/inbound.py src/alfred/comms_mcp/bootstrap.py tests/unit/comms_mcp/test_bootstrap.py tests/unit/comms_mcp/_inbound_spies.py tests/integration/test_discord_subpayload_promotion.py tests/integration/test_discord_addressing_modes.py tests/integration/test_tui_round_trip.py
git commit -m "feat(comms): carry display_name on ResolvedInbound to the ingest seam #338"
```

---

### Task 3: DI-refactor `build_orchestrator`

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py:459-508` (`build_orchestrator`)
- Test: `tests/integration/test_orchestrator_bootstrap.py`

**Interfaces:**

- Consumes: `build_broker(settings) -> SecretBroker` (`:110`), `build_router(broker, settings) -> ProviderRouter` (`:149`), `install_identity_factories_for_settings(settings) -> IdentityResolver` (`:211`, PROCESS-GLOBAL side effect), `build_session_scope(settings)` (from `alfred.memory.db`), `build_budget_guard(resolver, settings) -> BudgetGuard` (`:395`).
- Produces: `build_orchestrator(settings, *, broker=None, router=None, resolver=None, session_scope=None, quarantined_extractor=None) -> Orchestrator` — each pre-built component is used verbatim when provided, else built. PR2's daemon boot graph passes the graph's already-built `broker`/`resolver`/`session_scope` so neither the broker is double-built nor `install_identity_factories_for_settings` re-fired.

- [ ] **Step 1: Write the failing tests** (append to `tests/integration/test_orchestrator_bootstrap.py`; these are construction-shape tests — they can be plain `def` unit-style tests using monkeypatch, no DB needed):

```python
def test_build_orchestrator_reuses_injected_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Injected broker/router/resolver/session_scope are NOT rebuilt, and the
    process-global identity-factory install is NOT re-fired (FOLD-1, #338).

    Construction-only: no DB container — session_scope is injected and
    build_budget_guard/Orchestrator.__init__ open no connection at build time.
    """
    from unittest.mock import MagicMock

    build_broker_spy = MagicMock(side_effect=AssertionError("broker rebuilt"))
    build_router_spy = MagicMock(side_effect=AssertionError("router rebuilt"))
    build_session_scope_spy = MagicMock(side_effect=AssertionError("session_scope rebuilt"))
    install_spy = MagicMock(side_effect=AssertionError("identity factories re-fired"))
    monkeypatch.setattr(_bootstrap, "build_broker", build_broker_spy)
    monkeypatch.setattr(_bootstrap, "build_router", build_router_spy)
    monkeypatch.setattr(_bootstrap, "build_session_scope", build_session_scope_spy)
    monkeypatch.setattr(
        _bootstrap, "install_identity_factories_for_settings", install_spy
    )

    # Settings reads env only (no connection until session_scope is used, which
    # is injected here) — mirror the env pinning the other tests use (:111-116).
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setenv(
        "ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-bootstrap-test-placeholder"
    )
    settings = Settings()  # type: ignore[call-arg]  # reason: Settings.__init__ is untyped pending task-17

    orch = _bootstrap.build_orchestrator(
        settings,
        broker=MagicMock(),
        router=MagicMock(),
        # A MagicMock resolver satisfies the ctor's get_operator()/version_counter reads.
        resolver=MagicMock(),
        session_scope=MagicMock(),
    )
    assert isinstance(orch, Orchestrator)
    build_broker_spy.assert_not_called()
    build_router_spy.assert_not_called()
    build_session_scope_spy.assert_not_called()
    install_spy.assert_not_called()
```

(`Settings`, `_bootstrap`, `Orchestrator`, and `pytest` are already imported at the top of `test_orchestrator_bootstrap.py`. This test opens no `PostgresContainer` — it lives beside the other `build_orchestrator` tests for locality but is construction-only.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/integration/test_orchestrator_bootstrap.py::test_build_orchestrator_reuses_injected_components -v`
Expected: FAIL — `build_orchestrator()` got an unexpected keyword argument `broker` (current signature only accepts `quarantined_extractor`).

- [ ] **Step 3: Refactor `build_orchestrator`**

Replace the builder body (`_bootstrap.py:459-508`) so each component is use-or-build (keep the existing docstring intent + the `# type: ignore` on `build_budget_guard`):

```python
def build_orchestrator(
    settings: Settings,
    *,
    broker: SecretBroker | None = None,
    router: ProviderRouter | None = None,
    resolver: IdentityResolver | None = None,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
    quarantined_extractor: QuarantinedExtractorLike | None = None,
) -> Orchestrator:
    """Assemble a privileged :class:`Orchestrator` from operator settings.

    The daemon inbound assembly (#338 PR2) injects the boot graph's
    already-built ``broker``/``router``/``resolver``/``session_scope`` so the
    broker is not double-built and the PROCESS-GLOBAL
    ``install_identity_factories_for_settings`` (which keeps the version
    counter coherent across surfaces) is not re-fired. Each param defaults to
    ``None`` -> build it, so existing callers are unchanged. ``quarantined_extractor``
    is injected, never built here (PR-S4-11c-2).
    """
    broker = broker if broker is not None else build_broker(settings)
    router = router if router is not None else build_router(broker, settings)
    resolver = (
        resolver
        if resolver is not None
        else install_identity_factories_for_settings(settings)
    )
    session_scope = (
        session_scope if session_scope is not None else build_session_scope(settings)
    )
    budget = build_budget_guard(resolver, settings)  # type: ignore[arg-type]  # reason: resolver.version_counter is the dynamically-promoted PR-B Phase 1 attribute; Phase 5 lifts it to a typed property
    return Orchestrator(
        identity_resolver=resolver,
        session_scope=session_scope,
        router=router,
        budget=budget,
        episodic_factory=_episodic_factory,
        quarantined_extractor=quarantined_extractor,
    )
```

Keep the existing `# sec-001 / #370` comment about `build_broker` vs `build_broker_or_die` adjacent to the broker line. Ensure `ProviderRouter` and `IdentityResolver` are imported in `_bootstrap.py` (they are — `install_identity_factories_for_settings` returns `IdentityResolver`; `build_router` returns `ProviderRouter`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/integration/test_orchestrator_bootstrap.py -v`
Expected: PASS — the new injection test AND the existing `build_orchestrator(settings, quarantined_extractor=...)` tests at `:134`/`:143` (default path still builds).

- [ ] **Step 5: Type-check**

Run: `uv run mypy src/alfred/cli/_bootstrap.py && uv run pyright src/alfred/cli/_bootstrap.py`
Expected: no new errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/_bootstrap.py tests/integration/test_orchestrator_bootstrap.py
git commit -m "refactor(bootstrap): make build_orchestrator dependency-injectable #338"
```

---

### Task 4: Full verification + open the PR

**Files:** none (verification only).

- [ ] **Step 1: Run the full quality gate**

Run: `make check`
Expected: PASS (lint + format + mypy + pyright + unit + integration). If the macOS integration lane flakes under load, verify the specific suspects in isolation and trust Linux CI (do NOT weaken anything). Confirm the real exit code (do not pipe through `tail`).

- [ ] **Step 2: Confirm behaviour-neutrality**

Run: `grep -rn "egress_context\|RealTurnOrchestratorAdapter\|IOPlaneUnavailableError" src/alfred/cli/daemon/`
Expected: NO matches (PR1 does not touch the daemon boot path — the echo adapter is still what boots).

- [ ] **Step 3: Push + open the PR**

```bash
git push -u origin 338-real-llm-turn-graduation
gh pr create --title "feat(#338): PR1 — core seams for real-turn graduation" \
  --body "Behaviour-neutral seams for the #338 daemon cutover (PR2), no live caller. (1) optional egress_context on the privileged turn; (2) display_name on ResolvedInbound threaded to the ingest seam; (3) build_orchestrator dependency-injectable (FOLD-1 — avoids double-building the broker + re-firing the process-global identity factories). Spec: docs/superpowers/specs/2026-07-08-issue-338-real-llm-turn-graduation-design.md (rev.2). Refs #338."
```

- [ ] **Step 4: Run the full `/review-pr` fleet (security ALWAYS) + BOTH CodeRabbit (CLI `--base origin/main` + cloud); resolve every thread; merge on green with `gh pr merge --rebase` (NEVER `--admin`).**

## Definition of Done

- [ ] `handle_user_message` + `_handle_turn` accept an optional `egress_context`; a provided context is used at `core.py:762`, `None` synthesizes; both branches tested; all existing orchestrator callers unchanged.
- [ ] `ResolvedInbound` carries `display_name`, populated by the identity bridge from the resolved `User`, and forwarded into the inbound `ingest(...)` call; all 5 constructor sites updated; the echo adapter is unaffected (ignores the kwarg).
- [ ] `build_orchestrator` accepts optional pre-built `broker`/`router`/`resolver`/`session_scope`; injecting them skips the corresponding builders AND does not re-fire `install_identity_factories_for_settings`; the default (no-injection) path is byte-for-byte unchanged and the existing `test_orchestrator_bootstrap.py` callers pass.
- [ ] No production consumer of any seam exists; `grep` confirms the daemon boot path is untouched.
- [ ] `make check` green; `mypy --strict` + `pyright` clean; no `src/alfred/security/` changes.
- [ ] Every commit subject carries a literal `#338` after the colon.
