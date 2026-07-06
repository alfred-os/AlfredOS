# #339 PR3 — Agentic Act-Phase Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the orchestrator's single `router.complete` (the Act phase) with an agentic tool-calling loop that advertises the `ToolRegistry`'s tools, dispatches each requested tool through the merged PR2 `dispatch_tool` chokepoint in deterministic order, feeds the schema-extracted T2 result back to the planner, and re-completes until the model stops asking for tools — under AlfredOS's per-iteration budget, ordered-`call_index`, and connectivity-free trust-boundary constraints.

**Architecture:** The loop lives entirely inside `Orchestrator._handle_turn`, still wrapped by the existing `DeadlineWrapper.run(...)` (so the per-action deadline already bounds every iteration — core-004 resolves without new deadline plumbing). Tools, gate, and DLP arrive as **optional additive constructor seams** (mirroring the existing `quarantined_extractor=` seam); with an empty/absent registry the loop runs exactly one completion and reproduces today's single-completion turn byte-for-byte. In-turn tool messages are **ephemeral** (a local list discarded after the turn) so only the final assistant answer persists — no `Episode.role` migration. This PR also seeds the three production first-party grants the live T3 path needs and extends the boot-grant assertion to verify them on the correct axis. This is **mechanism proven by fixtures/integration**; the live comms cutover stays #338.

**Tech Stack:** Python 3.14+, asyncio, Pydantic v2 (`frozen, extra="forbid"`), pytest + `unittest.mock` (`AsyncMock`), structlog, `mypy --strict` + pyright, `ruff`, Babel (`pybabel` i18n catalog), the merged PR1 provider tool-protocol seam + PR2 `dispatch_tool` / `ToolRegistry` / `build_tool_registry`.

## Global Constraints

- **Python floor `>=3.14.6`; modern idioms only** — PEP 604 unions (`X | Y`), PEP 585 built-in generics, `Mapping` over `dict` for read-only inputs. Never `Optional[X]` / `typing.List`.
- **Immutability by default** — `Message` / `CompletionRequest` / `ToolCall` are `frozen, extra="forbid"`; construct new objects, never mutate.
- **HARD security rule #2 — never bypass the capability layer**; even in tests use a fixture grant (`make_tool_dispatch_gate` / `_assembly_gate`), never an always-allow stub.
- **HARD security rule #5 — the privileged orchestrator never sees raw T3.** The loop feeds back ONLY the `dispatch_tool` return value (already extracted + downgrade-cleared + DLP-scanned T2).
- **HARD security rule #7 — no silent failures in security paths.** `dispatch_tool` escalations (`InboundCanaryTripped`, `OutboundCanaryTripped`, downgrade-clearance `AlfredError`) MUST propagate (halt the turn); the loop never swallows them and never `except`-catches `asyncio.CancelledError` (it must reach the existing top-level timeout/cancel arm).
- **NEVER `asyncio.gather()` the tool calls** — dispatch is sequential in `response.tool_calls` order; `call_index` is a per-turn monotonic ordinal incremented once per dispatch (egress or not). This is the egress-id replay invariant (spec §5).
- **i18n rule #1 — all operator/user-facing strings through `t()`.** New loop/refusal messages get catalog keys; `pybabel extract` (pre-commit) + `pybabel compile --check` (CI) must stay green.
- **Adversarial suite is release-blocking for `src/alfred/security/` changes** (Task 4 touches `capability_gate/`). Run the full `tests/adversarial` suite before push.
- **Run FULL `tests/unit` before every push** — the line-pinned audit AST guard (`tests/unit/audit/test_audit_log_result_domain_closed.py`) is missed by a scoped run.
- **Lint plan/docs before commit** — MD031 (blanks around fences) / MD032 (blanks around lists); the writing-plans template emits fences+lists without blank lines.
- **Commit subjects** carry a literal `#339` (Conventional-commit required check) and end with the `MrReasonable` trailer.

---

## Scope reconciliation (READ FIRST — decided on best judgment; open to veto at plan-review)

Spec §11's PR3 row is **loop-only**. PR2's memory notes piled three further obligations onto "PR3": (a) seed the 3 production first-party grants, (b) convert the 2 strict-`xfail` merge-blockers, (c) carry the four #347 blockers. Bundling all of it makes PR3 span three distinct responsibilities and violates the small-PR rule. The user was away when asked; this plan proceeds on **Option A (focused)** and documents it here for veto:

**IN this PR3:**

- The agentic act-phase loop (§6/§7/§9/§10) — the one deliverable spec §11 names.
- Seed the **3 production first-party grants** (`tool.dispatch`, `quarantine.dereference`, `t3.downgrade_to_orchestrator`) + extend the boot-grant assertion. Rationale: the production T3 path fails loud (`downgrade_denied`) without them, #338 needs them imminently, and they pair naturally with the loop (the loop is what dispatches tools). This is the one **bolded HARD deliverable** in the launch prompt.

**DEFERRED to PR4 (the live-caller-readiness + corpus-breadth + real-LLM-smoke PR):**

- Converting `test_inbound_canary_unwired_deferred_to_339` (needs a core-side canary-token source + threading a real `CanaryMatcher` into `build_web_fetch_egress_extractor`) and `test_per_user_exhaustion_refusal_deferred_to_339` (reinstate the per-user `handle_cap`). Both are `xfail(strict=True)` and stay **green XFAIL** until someone sets `canary != None` / reinstates the cap — so deferring does **not** break CI, and they remain #339-epic merge-blockers (PR4 is inside #339).
- The four #347 blockers (`User.language` sourcing, live-relay `TimeoutError`/`in_doubt` cross-layer audit test, per-user resource bound, broker auth). These are properties of the **web.fetch egress live path**, whose first live exercise is PR4.

**Justification the launch prompt itself supports:** it frames the live cutover as #338 ("PR3 likely wires the loop into the Act phase proven by fixtures/integration"), and the two xfails read "before the first live caller merges" — the first live caller is #338 (or PR4's real-LLM smoke), not PR3's fixture-proven loop. If plan-review or the user rejects this, promote the deferred items into new Tasks 7–8; the loop tasks (1–6) are unaffected.

**Also deferred (YAGNI, documented):** wiring `build_tool_registry` into `build_orchestrator` (`cli/_bootstrap.py:459`). `build_orchestrator` is the unwired #338 graduation site and does not construct the quarantine graph (gate/extractor/recorder/dlp/session_scope/rate_limiter/config) the registry needs. PR3 adds the **Orchestrator constructor seams** and proves the loop by constructing the orchestrator directly in the integration test (the "test is the proof, not a live caller" precedent — ADR-0041 / tool_assembly.py). #338 supplies the live registry through `build_orchestrator`.

---

## File structure

**Modified:**

- `src/alfred/orchestrator/core.py` — add optional `tool_registry` / `gate` / `outbound_dlp` constructor seams + loop constants + the `_synthesize_egress_context` helper + the act-phase loop replacing the single `router.complete` (lines ~741–867). One responsibility grows: the Act phase.
- `src/alfred/security/capability_gate/_bootstrap_grants.py` — add the 3 first-party grants to `FIRST_PARTY_SYSTEM_GRANTS`.
- `src/alfred/cli/daemon/_gate_boot.py` — extend `_first_party_grant_live` to verify content grants via `check_content_clearance` and subscriber grants via `check`.
- `locale/en/LC_MESSAGES/alfred.po` + `alfred.mo` — new `orchestrator.tool.*` loop-message keys (via `pybabel`).
- `docs/adr/0026-first-party-system-grants.md` — dated factual amendment listing the 3 new grants.
- `tests/unit/orchestrator/test_core.py` — update the ~2 `provider_call` phase assertions to `provider_call:0` (the loop indexes the phase per spec §10).
- `tests/unit/security/capability_gate/test_bootstrap_grants.py` — update the `expected == FIRST_PARTY_SYSTEM_GRANTS` exact-equality pin (+3 rows).

**Created:**

- `src/alfred/orchestrator/loop_constants.py` — `MAX_TOOL_ITERATIONS`, `MAX_TOOL_CALLS_PER_ITERATION`, `TOOL_RESULT_MAX_CHARS` (kept out of `core.py` so tests can import + patch them without importing the whole orchestrator).
- `tests/unit/orchestrator/test_act_loop.py` — loop-control unit tests (fake registry/dispatch): single-completion regression, ordered `call_index`, no-gather, fan-out cap, max-iterations, mid-turn budget break, negative-persistence, per-iteration `provider_failed`.
- `tests/integration/orchestrator/test_act_loop_real_chain.py` — the 2-tool loop over the real `build_tool_registry` chain + `_assembly_gate` (web.fetch T3 leg + clock.now internal leg) on a loopback relay.
- `tests/unit/security/capability_gate/test_first_party_grants_live.py` — assert all 3 seeded grants are live on the boot gate via the correct check axis.

---

## Interfaces reference (verified against the merged tree — copy these signatures exactly)

```python
# src/alfred/orchestrator/tool_dispatch.py  (PR2, MERGED)
async def dispatch_tool(
    call: ToolCall,
    call_index: int,
    *,
    ctx: TurnEgressContext,
    registry: ToolRegistry,
    gate: CapabilityGate,
    dlp: OutboundDlpProtocol,
    audit: AuditWriter,
    user_id: str,
    correlation_id: str,
    language: str | None,
) -> str: ...            # returns a T2 tool_result string OR re-raises on escalation

# src/alfred/orchestrator/tool_registry.py  (PR2, MERGED)
class ToolRegistry:
    def get(self, name: str) -> ToolSpec | None: ...
    def definitions(self) -> tuple[ToolDefinition, ...]: ...   # advertise to the planner

# src/alfred/egress/egress_id.py  (MERGED)
class TurnEgressContext(BaseModel):     # frozen; adapter_id / inbound_id / session_id : str
    adapter_id: str
    inbound_id: str
    session_id: str

# src/alfred/providers/base.py  (PR1, MERGED)
class ToolCall(BaseModel):   # frozen; id: str; name: str; arguments: Mapping[str, JsonValue]
class Message(BaseModel):    # frozen; role, content="", tool_calls=(), tool_call_id=None
                             #   validator: role=="tool" <=> tool_call_id set; tool_calls only on assistant
class CompletionRequest(BaseModel):   # + tools: tuple[ToolDefinition,...] = (); tool_choice: ToolChoice = "auto"
class CompletionResponse(BaseModel):  # + stop_reason: StopReason="end_turn"; tool_calls: tuple[ToolCall,...]=()
                             #   validator: stop_reason=="tool_use" requires non-empty tool_calls

# src/alfred/budget/guard.py  (MERGED)
class BudgetGuard:
    def estimate_for(self, user_id: str, _request: CompletionRequest) -> float: ...   # raises UnknownBudgetUserError
    def would_exceed(self, user_id: str, cost_usd: float) -> bool: ...                 # raises ValueError/UnknownBudgetUserError
    def check_and_charge(self, user_id: str, cost_usd: float) -> None: ...             # raises ValueError/PerCallCapExceededError/UnknownBudgetUserError/BudgetExceededError
# BudgetError (base); PerCallCapExceededError; UnknownBudgetUserError(*, user_id); BudgetExceededError(*, spent_usd, cap_usd)
```

---

### Task 1: Loop constants module + Orchestrator constructor seams + egress-context synthesis

**Files:**

- Create: `src/alfred/orchestrator/loop_constants.py`
- Modify: `src/alfred/orchestrator/core.py` (imports; `Orchestrator.__init__` signature ~233-269 + attribute assignment ~276-299; add `_synthesize_egress_context` method near the other `_` helpers)
- Test: `tests/unit/orchestrator/test_act_loop.py` (new — constructor + synthesizer tests only in this task)

**Interfaces:**

- Consumes: `TurnEgressContext` from `alfred.egress.egress_id`; the existing `Orchestrator.__init__` keyword-only shape.
- Produces:
  - `loop_constants.MAX_TOOL_ITERATIONS: int` (`8`), `MAX_TOOL_CALLS_PER_ITERATION: int` (`8`), `TOOL_RESULT_MAX_CHARS: int` (`8192`).
  - `Orchestrator.__init__(..., tool_registry: ToolRegistry | None = None, gate: CapabilityGate | None = None, outbound_dlp: OutboundDlpProtocol | None = None)` storing `self._tool_registry` / `self._gate` / `self._outbound_dlp`.
  - `Orchestrator._synthesize_egress_context(self, *, trace_id: str, user: UserLike) -> TurnEgressContext`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/orchestrator/test_act_loop.py
"""Unit tests for the #339 PR3 agentic act-phase loop (core.py _handle_turn)."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.orchestrator import loop_constants
from alfred.orchestrator.core import Orchestrator


def _make_orchestrator(*, router: Any = None, budget: Any = None, **kw: Any) -> Orchestrator:
    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=MagicMock())
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    return Orchestrator(
        identity_resolver=resolver,
        session_scope=_scope,
        router=router if router is not None else MagicMock(),
        budget=budget if budget is not None else MagicMock(),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        **kw,
    )


def test_constructor_defaults_tool_seams_to_none() -> None:
    orch = _make_orchestrator()
    assert orch._tool_registry is None
    assert orch._gate is None
    assert orch._outbound_dlp is None


def test_loop_constants_are_positive_ints() -> None:
    assert loop_constants.MAX_TOOL_ITERATIONS > 0
    assert loop_constants.MAX_TOOL_CALLS_PER_ITERATION > 0
    assert loop_constants.TOOL_RESULT_MAX_CHARS > 0


def test_synthesize_egress_context_is_deterministic_for_the_turn() -> None:
    orch = _make_orchestrator()
    user = MagicMock()
    user.slug = "alice"
    ctx_a = orch._synthesize_egress_context(trace_id="trace-1", user=user)
    ctx_b = orch._synthesize_egress_context(trace_id="trace-1", user=user)
    assert isinstance(ctx_a, TurnEgressContext)
    assert ctx_a == ctx_b                      # replay-stable within the turn
    assert ctx_a.inbound_id == "trace-1"       # committed inbound identity == trace_id (fixture path)
    other = orch._synthesize_egress_context(trace_id="trace-2", user=user)
    assert other != ctx_a                       # distinct turns -> distinct anchors
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v`
Expected: FAIL — `AttributeError: 'Orchestrator' object has no attribute '_tool_registry'` and `ModuleNotFoundError: alfred.orchestrator.loop_constants`.

- [ ] **Step 3: Create the constants module**

```python
# src/alfred/orchestrator/loop_constants.py
"""Bounds for the #339 PR3 agentic act-phase loop (spec §7/§9).

Kept in a tiny standalone module so tests can import + monkeypatch them
without importing the whole orchestrator, and so the numeric policy lives
in one greppable place. The per-action DEADLINE (``DeadlineWrapper`` in
``handle_user_message``) is the real wall-clock bound (core-004); these are
cost / fan-out backstops that bound spend and provider round-trips.
"""

from __future__ import annotations

from typing import Final

# Max privileged-planner completions per turn. A backstop under the outer
# action-deadline: bounds total spend + provider round-trips if a model
# loops on tool calls without converging.
MAX_TOOL_ITERATIONS: Final[int] = 8

# Max tool calls honoured from a SINGLE completion. Bounds intra-iteration
# egress fan-out (one completion could otherwise request N tools that all
# fire before the next per-iteration budget check — mem-003/core-006).
MAX_TOOL_CALLS_PER_ITERATION: Final[int] = 8

# Max chars of a tool_result fed back to the planner. Caps context growth +
# a pathological tool from ballooning the next request (spec §6).
TOOL_RESULT_MAX_CHARS: Final[int] = 8192
```

- [ ] **Step 4: Add the constructor seams + synthesizer to `core.py`**

Add to the `TYPE_CHECKING` / import block (top of `core.py`) — reuse existing import style:

```python
from alfred.egress.egress_id import TurnEgressContext

if TYPE_CHECKING:
    from alfred.hooks.capability import CapabilityGate
    from alfred.orchestrator.tool_registry import ToolRegistry
    from alfred.security.dlp import OutboundDlpProtocol
```

Extend `Orchestrator.__init__` — add these keyword-only params after `quarantined_extractor` (keep the existing docstring rationale; these mirror its additive-optional shape):

```python
        # #339 PR3: the agentic act-phase loop seams. Additive + optional so
        # every Slice-1..4 caller that omits them keeps constructing and the
        # loop degrades to today's single completion (empty registry ->
        # tools=() -> stop_reason "end_turn" on iteration 0). The daemon
        # inbound assembly (#338) injects the live registry/gate/dlp.
        tool_registry: ToolRegistry | None = None,
        gate: CapabilityGate | None = None,
        outbound_dlp: OutboundDlpProtocol | None = None,
    ) -> None:
```

Assign in the body (alongside `self._quarantined_extractor = quarantined_extractor`):

```python
        self._tool_registry = tool_registry
        self._gate = gate
        self._outbound_dlp = outbound_dlp
```

Add the synthesizer method (place it near `_audit_unknown_budget_user`):

```python
    def _synthesize_egress_context(
        self, *, trace_id: str, user: UserLike
    ) -> TurnEgressContext:
        """Build the per-turn egress anchor for the fixture / ``alfred chat`` path.

        #339 is mechanism-proven-by-fixtures: there is no live comms resume, so
        the anchor is synthesized DETERMINISTICALLY from the turn identity (as
        G7-2's synthetic driver did). ``inbound_id`` is the turn ``trace_id``
        (the committed inbound identity on this path); ``session_id`` is the
        requesting user's slug. #338 REPLACES this synthesis with the real
        adapter/inbound/session identity carried by the live comms inbound.

        Replay note (spec §5): within a turn the same ``trace_id`` yields the
        same anchor, so ``compute_egress_id(ctx, call_index)`` is stable for a
        fixed dispatch sequence. Cross-turn at-most-once under re-planning is a
        hard #338 prerequisite (journal the dispatch sequence), NOT provided
        here — #339 has no live resume so it is not reachable.
        """
        return TurnEgressContext(
            adapter_id="orchestrator.synthetic",
            inbound_id=trace_id,
            session_id=user.slug,
        )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Type-check + lint the touched files**

Run: `uv run mypy src/alfred/orchestrator/core.py src/alfred/orchestrator/loop_constants.py && uv run ruff check src/alfred/orchestrator/ tests/unit/orchestrator/test_act_loop.py`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/orchestrator/loop_constants.py src/alfred/orchestrator/core.py tests/unit/orchestrator/test_act_loop.py
git commit -m "feat(orchestrator): loop constants + act-phase constructor seams (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: Loop skeleton — iterate while preserving the single-completion turn (no tools)

**Files:**

- Modify: `src/alfred/orchestrator/core.py` (`_handle_turn` Act region, lines ~741-867 — replace the single `router.complete` + charge + persist with a bounded loop that runs exactly one iteration when no tools are advertised)
- Modify: `tests/unit/orchestrator/test_core.py` (update ~2 `provider_call` phase assertions to `provider_call:0`)
- Test: `tests/unit/orchestrator/test_act_loop.py` (add the no-tools regression + phase-index tests)

**Interfaces:**

- Consumes: Task-1 seams + `loop_constants`; the existing `self._budget` / `self._router` / `self._audit` / `self._redactor` / working-memory / episodic machinery.
- Produces: a `_handle_turn` whose Act phase is a `for iteration in range(MAX_TOOL_ITERATIONS)` loop. With `self._tool_registry is None` it runs one iteration and returns `response.content` — identical persistence + audit to today, except the provider-call audit `phase` is now `f"provider_call:{iteration}"` and the loop threads a per-turn spend accumulator + `final_*` bindings the tool path (Task 3) reuses.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/orchestrator/test_act_loop.py  (append)
from alfred.providers.base import CompletionResponse


def _text_response(content: str = "hello", cost: float = 0.01) -> CompletionResponse:
    return CompletionResponse(
        content=content, tokens_in=5, tokens_out=3, cost_usd=cost, model="fake",
        stop_reason="end_turn", tool_calls=(),
    )


@pytest.mark.asyncio
async def test_no_tools_runs_exactly_one_completion(monkeypatch: Any) -> None:
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("final answer"))
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=0.0)
    budget.would_exceed = MagicMock(return_value=False)
    budget.check_and_charge = MagicMock(return_value=None)
    orch = _make_orchestrator(router=router, budget=budget)  # tool_registry defaults None

    reply = await _drive_turn(orch)                 # helper defined below
    assert reply == "final answer"
    assert router.complete.await_count == 1         # one iteration, no tools


@pytest.mark.asyncio
async def test_provider_call_audit_phase_is_indexed(monkeypatch: Any) -> None:
    audit_rows = await _drive_turn_capturing_audit(_text_response("ok"))
    phases = [r["subject"].get("phase") for r in audit_rows]
    assert "provider_call:0" in phases               # spec §10 indexed phase
    assert "completed" in phases                     # terminal row unindexed
```

Add two small drivers at the top of the test module (they build the real `TaggedContent` + `WorkingMemory` the turn needs; reuse `test_core.py`'s construction pattern — see that file for `TaggedContent`/`WorkingMemory` imports and the `_make_working_memory` shape):

```python
# tests/unit/orchestrator/test_act_loop.py  (helpers — mirror test_core.py's turn drivers)
from alfred.security.tiers import T2, TaggedContent
# NOTE: copy test_core.py's exact WorkingMemory + TaggedContent construction
# helper here (it wires an in-memory working buffer + a T2-tagged user turn);
# do NOT re-implement from scratch — reuse the proven shape so the driver
# exercises the same observe/orient path production uses.
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -k "no_tools or indexed" -v`
Expected: FAIL — the audit phase is still `"provider_call"` (unindexed), and there is no loop yet.

- [ ] **Step 3: Replace the Act region of `_handle_turn` with the loop skeleton**

In `core.py`, replace the block from the `# Act` comment (~741) through the `return response.content` (~867) with the following. This preserves EVERY existing behavior for the no-tools path (iteration-0 pre-check raise, `provider_failed` arm, charge force-record, `UnknownBudgetUserError` re-raise arms, persist + `completed` audit) and adds the loop scaffold Task 3 fills in at the marked hook:

```python
        # ------------------------------------------------------------------
        # Act — the agentic tool-calling loop (#339 PR3, spec §6/§7/§9).
        #
        # The per-action DEADLINE (DeadlineWrapper in handle_user_message)
        # bounds the WHOLE loop; MAX_TOOL_ITERATIONS is the cost/round-trip
        # backstop under it (core-004). asyncio.CancelledError from the
        # deadline is NOT caught here — it propagates to the top-level
        # timeout/cancel arm (hard rule #7). dispatch_tool escalations
        # (canary / downgrade-deny) likewise propagate to halt the turn.
        # With no registry the loop runs exactly one iteration and reduces
        # to the pre-#339 single-completion turn.
        # ------------------------------------------------------------------
        tools = self._tool_registry.definitions() if self._tool_registry is not None else ()
        base_messages = messages                       # system + history (built in Orient)
        local: list[Message] = []                      # in-turn tool transcript (EPHEMERAL)
        call_index = 0
        per_turn_spent_usd = 0.0
        final_content: str | None = None
        final_response: CompletionResponse | None = None
        final_charge_result = "success"

        for iteration in range(MAX_TOOL_ITERATIONS):
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
            )

            # --- per-iteration budget pre-check (spec §7) ---
            try:
                estimate = self._budget.estimate_for(user.slug, request)
                would_exceed = self._budget.would_exceed(user.slug, estimate)
            except BudgetError as exc:
                if isinstance(exc, UnknownBudgetUserError):
                    await self._audit_unknown_budget_user(
                        user=user, trace_id=trace_id,
                        phase="budget_pre_check", trigger_tier=user_input_tier,
                    )
                raise
            if would_exceed:
                await self._audit.append(
                    event="orchestrator.turn",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject=_sanitize_subject(
                        {"phase": f"budget_pre_check:{iteration}", "estimate_usd": estimate},
                        self._redactor,
                    ),
                    trust_tier_of_trigger=user_input_tier,
                    result="budget_blocked",
                    cost_estimate_usd=estimate,
                    cost_actual_usd=0.0,
                    trace_id=trace_id,
                    language=user.language,
                    persona_id=_ALFRED_PERSONA_ID,
                )
                if iteration == 0:
                    # No spend yet — preserve the pre-#339 pre-check contract
                    # (adapters expect a raised BudgetError before iteration 0).
                    raise BudgetError(
                        f"pre-check refused: estimate ${estimate:.4f} would breach budget"
                    )
                # Mid-turn: we already have prior context — end gracefully.
                final_content = t("orchestrator.tool.budget_exhausted_mid_turn")
                break

            # --- completion (NEVER gather) ---
            try:
                response = await self._router.complete(request)
            except Exception as exc:
                _log.error(
                    "orchestrator.provider_failed",
                    trace_id=trace_id, iteration=iteration,
                    error=self._redactor(str(exc)), error_type=type(exc).__name__,
                )
                await self._audit.append(
                    event="orchestrator.turn",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject=_sanitize_subject(
                        {"phase": f"provider_call:{iteration}",
                         "error_type": type(exc).__name__, "error": str(exc)},
                        self._redactor,
                    ),
                    trust_tier_of_trigger=user_input_tier,
                    result="provider_failed",
                    cost_estimate_usd=estimate,
                    cost_actual_usd=0.0,
                    trace_id=trace_id,
                    language=user.language,
                    persona_id=_ALFRED_PERSONA_ID,
                )
                raise
            final_response = response

            # --- charge the actual cost; force-record on overrun (spec §7) ---
            charge_result = "success"
            try:
                self._budget.check_and_charge(user.slug, response.cost_usd)
            except BudgetError as exc:
                if isinstance(exc, UnknownBudgetUserError):
                    await self._audit_unknown_budget_user(
                        user=user, trace_id=trace_id,
                        phase="budget_post_charge", trigger_tier=user_input_tier,
                    )
                    raise
                charge_result = "budget_overrun"
                _log.warning(
                    "orchestrator.budget_overrun",
                    trace_id=trace_id, iteration=iteration,
                    estimate_usd=estimate, actual_usd=response.cost_usd,
                    error=self._redactor(str(exc)),
                )
            per_turn_spent_usd += response.cost_usd
            final_charge_result = charge_result
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {"phase": f"provider_call:{iteration}",
                     "model": response.model,
                     "tokens_in": response.tokens_in,
                     "tokens_out": response.tokens_out,
                     "charge_result": charge_result},
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input_tier,
                result=charge_result if charge_result == "budget_overrun" else "success",
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )

            # --- terminal? (no tool request -> final answer) ---
            if response.stop_reason != "tool_use" or not response.tool_calls:
                final_content = response.content
                break
            if charge_result == "budget_overrun":
                # Money already over cap AND the model wants more tools — stop
                # before dispatching further egress (spec §7).
                final_content = t("orchestrator.tool.budget_overrun_mid_turn")
                break

            # --- TOOL DISPATCH HOOK (Task 3 fills this in) ---
            raise NotImplementedError("tool dispatch lands in Task 3")
        else:
            # Loop exhausted MAX_TOOL_ITERATIONS without a terminal answer.
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject({"phase": "max_iterations_reached"}, self._redactor),
                trust_tier_of_trigger=user_input_tier,
                result="max_iterations_reached",
                cost_estimate_usd=0.0,
                cost_actual_usd=per_turn_spent_usd,
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )
            final_content = t("orchestrator.tool.max_iterations_reached")

        # ``final_response`` is None ONLY if iteration 0 raised (handled above),
        # so it is populated whenever control reaches here. ``final_content`` is
        # always set by a break arm or the for-else.
        assert final_response is not None
        answer = final_content if final_content is not None else final_response.content
```

Then, immediately below, KEEP the existing persist + `completed` audit + return, adapted to the new bindings (replace `response` with `final_response`, `charge_result` with `final_charge_result`, `response.content` with `answer`):

```python
        await working_memory.append(role="assistant", content=answer)
        await episodic.record(
            user_id=user.slug, role="assistant", content=answer, trust_tier="T2",
            tokens_in=final_response.tokens_in, tokens_out=final_response.tokens_out,
            cost_usd=final_response.cost_usd, language=user.language,
            persona=_ALFRED_PERSONA_ID, persona_id=_ALFRED_PERSONA_ID,
        )
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {"phase": "completed", "model": final_response.model,
                     "tokens_in": final_response.tokens_in,
                     "tokens_out": final_response.tokens_out,
                     "charge_result": final_charge_result,
                     "turn_cost_usd": per_turn_spent_usd},
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input_tier,
                result=final_charge_result if final_charge_result == "budget_overrun" else "success",
                cost_estimate_usd=0.0,
                cost_actual_usd=per_turn_spent_usd,
                trace_id=trace_id, language=user.language, persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception as exc:
            _log.error(
                "orchestrator.audit_write_failed",
                trace_id=trace_id, error=self._redactor(str(exc)),
                error_type=type(exc).__name__,
            )
            raise
        _log.info(
            "orchestrator.turn", trace_id=trace_id,
            tokens_in=final_response.tokens_in, tokens_out=final_response.tokens_out,
            cost_usd=per_turn_spent_usd, charge_result=final_charge_result,
        )
        return answer
```

Add the needed imports at the top of `core.py` if not already present: `from alfred.orchestrator.loop_constants import MAX_TOOL_ITERATIONS, MAX_TOOL_CALLS_PER_ITERATION, TOOL_RESULT_MAX_CHARS` and ensure `CompletionRequest, CompletionResponse, Message` are imported from `alfred.providers.base`.

- [ ] **Step 4: Update the pre-existing phase assertions in `test_core.py`**

Find the ~2 tests asserting `subject["phase"] == "provider_call"` (`test_provider_exception_is_audited_and_re_raised`, `test_provider_failure_subject_is_redacted`) and change the expected value to `"provider_call:0"`. Leave `budget_pre_check` / `budget_post_charge` / `completed` / `turn_cancelled` / `turn_timeout` assertions untouched (those phases stay unindexed).

- [ ] **Step 5: Run the full orchestrator unit suite**

Run: `uv run pytest tests/unit/orchestrator/test_core.py tests/unit/orchestrator/test_act_loop.py -q`
Expected: PASS — every pre-existing `test_core.py` behavior preserved (with the 2 phase-string updates), plus the new no-tools + indexed-phase tests. The `NotImplementedError` hook is unreached (no tools advertised).

- [ ] **Step 6: Type-check + lint**

Run: `uv run mypy src/alfred/orchestrator/core.py && uv run ruff check src/alfred/orchestrator/core.py tests/unit/orchestrator/`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/orchestrator/core.py tests/unit/orchestrator/test_core.py tests/unit/orchestrator/test_act_loop.py
git commit -m "feat(orchestrator): act-phase loop skeleton preserving single-completion turn (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: Tool advertisement, ordered dispatch, ephemeral transcript + loop caps + i18n keys

**Files:**

- Modify: `src/alfred/orchestrator/core.py` (replace the Task-2 `raise NotImplementedError` hook with the dispatch block; add a `_truncate_tool_result` helper)
- Modify: `locale/en/LC_MESSAGES/alfred.po` + `alfred.mo` (new `orchestrator.tool.*` keys via `pybabel`)
- Test: `tests/unit/orchestrator/test_act_loop.py` (ordered dispatch, no-gather, fan-out cap, max-iterations, negative-persistence)

**Interfaces:**

- Consumes: `dispatch_tool` (exact signature in the interfaces reference); `self._tool_registry` / `self._gate` / `self._outbound_dlp` / `self._audit` (Task 1); `self._synthesize_egress_context` (Task 1); `MAX_TOOL_CALLS_PER_ITERATION` / `TOOL_RESULT_MAX_CHARS`.
- Produces: the completed loop body — deterministic ordered dispatch (`call_index` monotonic, never `gather`), tool_result fed back as ephemeral `Message(role="tool", tool_call_id=..., content=truncate(...))`, fan-out cap enforcement.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/orchestrator/test_act_loop.py  (append)
from alfred.providers.base import ToolCall, ToolDefinition


def _tool_use_response(*calls: ToolCall, cost: float = 0.01) -> CompletionResponse:
    return CompletionResponse(
        content="", tokens_in=5, tokens_out=3, cost_usd=cost, model="fake",
        stop_reason="tool_use", tool_calls=calls,
    )


def _fake_registry(*names: str) -> Any:
    reg = MagicMock()
    reg.definitions = MagicMock(return_value=tuple(
        ToolDefinition(name=n, description=n, input_schema={"type": "object", "properties": {}})
        for n in names
    ))
    return reg


@pytest.mark.asyncio
async def test_two_tool_turn_dispatches_in_order_then_returns(monkeypatch: Any) -> None:
    # planner: iteration 0 asks for two tools; iteration 1 gives the final answer.
    r0 = _tool_use_response(
        ToolCall(id="c0", name="clock.now", arguments={}),
        ToolCall(id="c1", name="clock.now", arguments={}),
    )
    r1 = _text_response("done")
    router = MagicMock()
    router.complete = AsyncMock(side_effect=[r0, r1])
    budget = _ok_budget()                         # helper: estimate 0, never exceed, no-op charge

    seen: list[int] = []
    async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
        seen.append(call_index)
        return f"result-{call.id}"
    monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)

    orch = _make_orchestrator(
        router=router, budget=budget,
        tool_registry=_fake_registry("clock.now"),
        gate=MagicMock(), outbound_dlp=MagicMock(),
    )
    reply = await _drive_turn(orch)
    assert reply == "done"
    assert seen == [0, 1]                          # monotonic, in tool_calls order, no gather
    assert router.complete.await_count == 2        # re-completed after feeding results back


@pytest.mark.asyncio
async def test_fanout_over_cap_refuses(monkeypatch: Any) -> None:
    monkeypatch.setattr(loop_constants, "MAX_TOOL_CALLS_PER_ITERATION", 1)
    r0 = _tool_use_response(
        ToolCall(id="c0", name="clock.now", arguments={}),
        ToolCall(id="c1", name="clock.now", arguments={}),
    )
    router = MagicMock(); router.complete = AsyncMock(return_value=r0)
    orch = _make_orchestrator(
        router=router, budget=_ok_budget(),
        tool_registry=_fake_registry("clock.now"), gate=MagicMock(), outbound_dlp=MagicMock(),
    )
    reply = await _drive_turn(orch)
    from alfred.i18n import t
    assert reply == t("orchestrator.tool.too_many_tool_calls")


@pytest.mark.asyncio
async def test_max_iterations_reached(monkeypatch: Any) -> None:
    monkeypatch.setattr(loop_constants, "MAX_TOOL_ITERATIONS", 2)
    forever = _tool_use_response(ToolCall(id="c", name="clock.now", arguments={}))
    router = MagicMock(); router.complete = AsyncMock(return_value=forever)
    async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
        return "r"
    monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
    orch = _make_orchestrator(
        router=router, budget=_ok_budget(),
        tool_registry=_fake_registry("clock.now"), gate=MagicMock(), outbound_dlp=MagicMock(),
    )
    from alfred.i18n import t
    reply = await _drive_turn(orch)
    assert reply == t("orchestrator.tool.max_iterations_reached")
    assert router.complete.await_count == 2


@pytest.mark.asyncio
async def test_tool_results_never_persist_to_episodic(monkeypatch: Any) -> None:
    r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
    r1 = _text_response("final")
    router = MagicMock(); router.complete = AsyncMock(side_effect=[r0, r1])
    async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
        return "SENSITIVE-TOOL-BODY"
    monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
    episodic_rows = await _drive_turn_capturing_episodic(
        router=router, tool_registry=_fake_registry("clock.now")
    )
    contents = [r["content"] for r in episodic_rows]
    assert "SENSITIVE-TOOL-BODY" not in contents         # ephemeral: only user + final assistant persist
    assert "final" in contents
```

Add the `_ok_budget()` helper (estimate 0.0, `would_exceed` False, `check_and_charge` no-op) and the `_drive_turn_capturing_episodic` driver near the other helpers (capture the `EpisodicMemory.record` kwargs via a `MagicMock` episodic factory).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -k "two_tool or fanout or max_iterations or never_persist" -v`
Expected: FAIL — `NotImplementedError: tool dispatch lands in Task 3` and missing i18n keys.

- [ ] **Step 3: Add the i18n catalog keys**

Add these four `msgid`/`msgstr` pairs to `locale/en/LC_MESSAGES/alfred.po` (after the existing `orchestrator.tool.refused` block, ~line 2525), then compile:

```po
msgid "orchestrator.tool.too_many_tool_calls"
msgstr "That request needed too many tools at once, so I stopped for safety."

msgid "orchestrator.tool.max_iterations_reached"
msgstr "I reached the limit on tool steps for this request. Here's where I got to."

msgid "orchestrator.tool.budget_exhausted_mid_turn"
msgstr "I ran out of budget partway through this request."

msgid "orchestrator.tool.budget_overrun_mid_turn"
msgstr "This request went over budget, so I stopped before running more tools."
```

Run the drift-safe catalog cycle (NEVER `--omit-header`):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred --statistics
```

- [ ] **Step 4: Replace the dispatch hook + add the truncation helper**

Replace `raise NotImplementedError("tool dispatch lands in Task 3")` in `core.py` with:

```python
            # --- fan-out cap (spec §7, mem-003) ---
            if len(response.tool_calls) > MAX_TOOL_CALLS_PER_ITERATION:
                await self._audit.append(
                    event="orchestrator.turn",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject=_sanitize_subject(
                        {"phase": f"tool_fanout_exceeded:{iteration}",
                         "requested": len(response.tool_calls),
                         "cap": MAX_TOOL_CALLS_PER_ITERATION},
                        self._redactor,
                    ),
                    trust_tier_of_trigger=user_input_tier,
                    result="refused",
                    cost_estimate_usd=0.0, cost_actual_usd=0.0,
                    trace_id=trace_id, language=user.language, persona_id=_ALFRED_PERSONA_ID,
                )
                final_content = t("orchestrator.tool.too_many_tool_calls")
                break

            # --- echo the assistant's tool-request turn into the EPHEMERAL local transcript ---
            local.append(
                Message(role="assistant", content=response.content, tool_calls=response.tool_calls)
            )

            # --- deterministic ordered dispatch (NEVER gather; call_index monotonic) ---
            ctx = self._synthesize_egress_context(trace_id=trace_id, user=user)
            for call in response.tool_calls:
                result_t2 = await dispatch_tool(
                    call, call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                call_index += 1
                local.append(
                    Message(
                        role="tool",
                        tool_call_id=call.id,
                        content=_truncate_tool_result(result_t2),
                    )
                )
```

Add the import `from alfred.orchestrator.tool_dispatch import dispatch_tool` at the top of `core.py`, and this module-level helper:

```python
def _truncate_tool_result(text: str) -> str:
    """Bound a tool_result fed back to the planner (spec §6, TOOL_RESULT_MAX_CHARS).

    A pathological or verbose tool must not balloon the next completion's
    context. Truncates on a character boundary and appends an ellipsis marker
    so the planner can tell the result was clipped.
    """
    if len(text) <= TOOL_RESULT_MAX_CHARS:
        return text
    return text[:TOOL_RESULT_MAX_CHARS] + "…[truncated]"
```

**Escalation note (do NOT add a catch here):** `dispatch_tool` re-raises `InboundCanaryTripped` / `OutboundCanaryTripped` / the downgrade-clearance `AlfredError` on escalation, having already written its own loud audit row on an independent `AuditWriter` (survives the turn-session rollback). Those propagate out of the loop and `_handle_turn` to the top-level arm (halt the turn) — this is HARD rule #7 / spec §9 "canary → HALT, never a recoverable tool_result." Leave them uncaught. (Plan-review security lens: confirm no turn-level `orchestrator.turn` escalation row is additionally required; `dispatch_tool`'s dispatch-level row is the authoritative security audit.)

- [ ] **Step 5: Run the loop tests + full orchestrator suite**

Run: `uv run pytest tests/unit/orchestrator/ -q`
Expected: PASS — ordered `call_index` `[0, 1]`, no-gather, fan-out refusal, max-iterations message, negative-persistence, plus all Task-2 regressions.

- [ ] **Step 6: Type-check + lint + i18n check**

Run: `uv run mypy src/alfred/orchestrator/core.py && uv run ruff check src/alfred/orchestrator/ && uv run pybabel compile -d locale -D alfred --statistics`
Expected: clean; catalog compiles with 0 fuzzy/missing.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/orchestrator/core.py locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo tests/unit/orchestrator/test_act_loop.py
git commit -m "feat(orchestrator): ordered tool dispatch + ephemeral transcript + loop caps (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: Seed the 3 production first-party grants + faithful boot assertion

**Files:**

- Modify: `src/alfred/security/capability_gate/_bootstrap_grants.py` (`FIRST_PARTY_SYSTEM_GRANTS` += 3 rows)
- Modify: `src/alfred/cli/daemon/_gate_boot.py` (`_first_party_grant_live` — branch on `content_tier`)
- Modify: `docs/adr/0026-first-party-system-grants.md` (dated factual amendment)
- Modify: `tests/unit/security/capability_gate/test_bootstrap_grants.py` (update the `expected ==` pin)
- Test: `tests/unit/security/capability_gate/test_first_party_grants_live.py` (new)

**Interfaces:**

- Consumes: `GrantRow(plugin_id, subscriber_tier, hookpoint, content_tier, proposal_branch)`; `GatePolicy.check(*, plugin_id, hookpoint, requested_tier)` (subscriber axis) and `check_content_clearance(*, plugin_id, hookpoint, content_tier)` (content axis) — verified: they consult DIFFERENT axes.
- Produces: 3 new seeded grants live at boot; `_first_party_grant_live` verifying each on its correct axis.

**Security:** this touches `src/alfred/security/capability_gate/` — the adversarial suite is release-blocking (run it in Task 6). Request a security sign-off in review.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/security/capability_gate/test_first_party_grants_live.py
"""#339 PR3: the 3 tool-dispatch first-party grants are live on the boot gate,
each verified on its correct axis (subscriber vs content clearance)."""
from __future__ import annotations

from alfred.security.capability_gate._bootstrap_grants import FIRST_PARTY_SYSTEM_GRANTS
from alfred.security.capability_gate.policy import GatePolicy


def _policy() -> GatePolicy:
    return GatePolicy(grants=frozenset(FIRST_PARTY_SYSTEM_GRANTS))


def test_tool_dispatch_grant_is_live_on_subscriber_axis() -> None:
    assert _policy().check(
        plugin_id="alfred.orchestrator.tool_dispatch",
        hookpoint="tool.dispatch",
        requested_tier="system",
    )


def test_quarantine_dereference_grant_is_live_on_content_axis() -> None:
    assert _policy().check_content_clearance(
        plugin_id="alfred.quarantined-llm",
        hookpoint="quarantine.dereference",
        content_tier="T3",
    )


def test_downgrade_grant_is_live_on_content_axis() -> None:
    assert _policy().check_content_clearance(
        plugin_id="t3.downgrade_to_orchestrator",
        hookpoint="t3.downgrade_to_orchestrator",
        content_tier="T3",
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/security/capability_gate/test_first_party_grants_live.py -v`
Expected: FAIL — the 3 grants are not yet in `FIRST_PARTY_SYSTEM_GRANTS` (checks return `False`).

- [ ] **Step 3: Add the 3 grants**

In `_bootstrap_grants.py`, extend the `FIRST_PARTY_SYSTEM_GRANTS` tuple (after the existing DLP-subscriber row). Field values copied verbatim from the PR2 test fixtures (`make_tool_dispatch_gate` + the `test_tool_assembly._assembly_gate` third grant) so the seed matches the runtime `dispatch_tool` / `downgrade_to_orchestrator` / `quarantined_to_structured` gate queries:

```python
    # --- #339 PR3: the three grants the live agentic tool-dispatch T3 path
    # needs. Until seeded, a real turn's web.fetch dispatch fails LOUD
    # (downgrade_denied) at the second content-clearance boundary. Mirrors the
    # test fixtures tests.helpers.gates.make_tool_dispatch_gate() (grants 1+3)
    # and tests/integration/orchestrator/test_tool_assembly._assembly_gate()
    # (grant 2). ADR-0046 (dual-LLM tool-result flow) + ADR-0026.
    GrantRow(
        # dispatch_tool: gate.check(plugin_id=TOOL_DISPATCH_PLUGIN_ID,
        #   hookpoint="tool.dispatch", requested_tier="system").
        plugin_id="alfred.orchestrator.tool_dispatch",
        subscriber_tier="system",
        hookpoint="tool.dispatch",
        content_tier=None,
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
    GrantRow(
        # quarantined_to_structured: gate.check_content_clearance(
        #   plugin_id="alfred.quarantined-llm",
        #   hookpoint="quarantine.dereference", content_tier="T3").
        plugin_id="alfred.quarantined-llm",
        subscriber_tier="system",
        hookpoint="quarantine.dereference",
        content_tier="T3",
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
    GrantRow(
        # downgrade_to_orchestrator: gate.check_content_clearance(
        #   plugin_id="t3.downgrade_to_orchestrator",
        #   hookpoint="t3.downgrade_to_orchestrator", content_tier="T3").
        plugin_id="t3.downgrade_to_orchestrator",
        subscriber_tier="system",
        hookpoint="t3.downgrade_to_orchestrator",
        content_tier="T3",
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
```

Update the module docstring's "One row today" sentence to "Four rows today: the DLP subscriber + the three #339 tool-dispatch grants."

- [ ] **Step 4: Make the boot assertion axis-faithful**

In `_gate_boot.py`, replace the `all(...)` generator in `_first_party_grant_live` so content grants are checked on the content axis:

```python
    return all(
        (
            gate.check_content_clearance(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                content_tier=grant.content_tier,
            )
            if grant.content_tier is not None
            else gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
        )
        for grant in FIRST_PARTY_SYSTEM_GRANTS
    )
```

Update the `_first_party_grant_live` docstring to note the two-axis verification (subscriber-tier grants via `check`, content-tier grants via `check_content_clearance`).

- [ ] **Step 5: Update the exact-equality drift pin**

In `tests/unit/security/capability_gate/test_bootstrap_grants.py`, the `expected` tuple asserted `== FIRST_PARTY_SYSTEM_GRANTS` must gain the 3 new `GrantRow`s in the same order. Copy the exact field values from Step 3. (The `test_seeded_plugin_id_matches_dlp_subscriber_module` drift-guard is unaffected — it pins only the DLP-subscriber row's `plugin_id`.)

- [ ] **Step 6: Add the ADR amendment**

Append to `docs/adr/0026-first-party-system-grants.md`:

```markdown
## Amendment 2026-07-06 (#339 PR3) — tool-dispatch grants added

`FIRST_PARTY_SYSTEM_GRANTS` gains three rows so the live agentic tool-dispatch
T3 path clears its gate boundaries at boot (previously it would fail loud with
`downgrade_denied`):

| plugin_id | hookpoint | subscriber_tier | content_tier | axis |
| --- | --- | --- | --- | --- |
| `alfred.orchestrator.tool_dispatch` | `tool.dispatch` | `system` | — | `check` |
| `alfred.quarantined-llm` | `quarantine.dereference` | `system` | `T3` | `check_content_clearance` |
| `t3.downgrade_to_orchestrator` | `t3.downgrade_to_orchestrator` | `system` | `T3` | `check_content_clearance` |

These realize the ADR-0046 dual-LLM tool-result flow. The boot grant-assertion
(`_first_party_grant_live`) now verifies each grant on its correct axis. This is
a factual amendment (grant list); the ADR-0026 seed-then-load mechanism and the
mandatory-defence posture are unchanged.
```

- [ ] **Step 7: Run the security-gate unit tests**

Run: `uv run pytest tests/unit/security/capability_gate/ tests/unit/cli/daemon/ -q`
Expected: PASS — the new liveness test, the updated exact-equality pin, and the existing seed/boot-assertion tests all green.

- [ ] **Step 8: Type-check + lint + markdownlint the ADR**

Run: `uv run mypy src/alfred/security/capability_gate/_bootstrap_grants.py src/alfred/cli/daemon/_gate_boot.py && uv run ruff check src/alfred/security/ src/alfred/cli/daemon/ && npx markdownlint-cli2 docs/adr/0026-first-party-system-grants.md`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/security/capability_gate/_bootstrap_grants.py src/alfred/cli/daemon/_gate_boot.py docs/adr/0026-first-party-system-grants.md tests/unit/security/capability_gate/test_bootstrap_grants.py tests/unit/security/capability_gate/test_first_party_grants_live.py
git commit -m "feat(security): seed 3 first-party tool-dispatch grants + axis-faithful boot assertion (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: Integration test — 2-tool loop over the real quarantine chain

**Files:**

- Create: `tests/integration/orchestrator/test_act_loop_real_chain.py`

**Interfaces:**

- Consumes: `build_tool_registry` (production assembly), `make_tool_dispatch_gate` / the `_assembly_gate` three-grant composition, the loopback-relay fixture from `tests/integration/orchestrator/test_tool_assembly.py`, and `Orchestrator(... tool_registry=, gate=, outbound_dlp=)`.
- Produces: proof that the loop drives the REAL T3 leg (web.fetch → `dispatch_web_fetch` → `quarantined_to_structured` → `downgrade_to_orchestrator` → DLP → T2) with the planner never seeing raw T3, plus the internal `clock.now` leg proving `call_index` increments on a non-egress dispatch.

- [ ] **Step 1: Write the failing integration test**

Reuse `test_tool_assembly.py`'s loopback relay + `build_tool_registry` wiring (import its fixtures / `_assembly_gate`; do NOT re-derive the upstream). Drive an `Orchestrator` whose `router.complete` is a scripted fake planner:

```python
# tests/integration/orchestrator/test_act_loop_real_chain.py  (skeleton — fill from test_tool_assembly fixtures)
@pytest.mark.integration
@pytest.mark.asyncio
async def test_loop_drives_real_web_fetch_then_clock_then_answers(assembly_env: Any) -> None:
    # assembly_env provides: a live loopback upstream, build_tool_registry(...)-built
    # registry (web.fetch + clock.now), the _assembly_gate (all 3 grants), the real
    # OutboundDlp, and a TurnEgressContext-compatible turn identity.
    registry = assembly_env.registry
    gate = assembly_env.gate
    dlp = assembly_env.outbound_dlp

    # Scripted planner: iter0 -> web.fetch(url=<loopback>); iter1 -> clock.now(); iter2 -> final.
    planner = _ScriptedRouter([
        _tool_use_response(ToolCall(id="w", name="web.fetch",
                                    arguments={"url": assembly_env.loopback_url})),
        _tool_use_response(ToolCall(id="k", name="clock.now", arguments={})),
        _text_response("synthesized answer"),
    ])
    orch = _build_orchestrator_with(router=planner, tool_registry=registry, gate=gate, outbound_dlp=dlp)

    reply = await _drive_turn(orch)

    assert reply == "synthesized answer"
    assert planner.complete.await_count == 3
    # The planner's second/third requests carried tool_result messages whose content
    # is the EXTRACTED T2 (WebFetchExtraction {text,intent} echo), never the raw upstream body.
    fed_back = planner.captured_tool_result_contents()
    assert all("raw-upstream-secret" not in c for c in fed_back)   # HARD rule #5
    # call_index incremented across BOTH an egress (web.fetch) and a non-egress (clock.now) dispatch.
    dispatch_rows = assembly_env.audit_rows(event="tool.dispatch")
    assert [r["subject"]["call_index"] for r in dispatch_rows] == [0, 1]
    assert {r["subject"]["tool_name"] for r in dispatch_rows} == {"web.fetch", "clock.now"}
```

- [ ] **Step 2: Run it to verify it fails, then passes**

Run: `uv run pytest tests/integration/orchestrator/test_act_loop_real_chain.py -v`
Expected first run: FAIL (test wiring incomplete / assertion mismatch). Iterate on the fixture reuse until it PASSES — the loop code from Tasks 1-3 is already complete, so failures here are test-wiring, not production bugs. If a production gap surfaces (e.g. a missing dispatch arg), fix it in `core.py` and note it.

- [ ] **Step 3: Type-check + lint**

Run: `uv run mypy tests/integration/orchestrator/test_act_loop_real_chain.py && uv run ruff check tests/integration/orchestrator/`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/orchestrator/test_act_loop_real_chain.py
git commit -m "test(orchestrator): integration 2-tool loop over the real quarantine chain (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 6: Docs, memory, spec status + full verification gates

**Files:**

- Modify: `docs/superpowers/specs/2026-07-05-issue-339-llm-tool-calling-design.md` (§11 PR3 row → mark loop shipped; note the Option-A deferrals to PR4)
- Modify: `docs/subsystems/security.md` (one line: the Act-phase loop is the live driver of the ADR-0046 T3 tool-result flow; 3 grants seeded)
- (No `CLAUDE.md` / `PRD.md` edits — human-gated.)

**Interfaces:** none (docs + verification).

- [ ] **Step 1: Update the spec §11 PR3 row + scope note**

In the spec, annotate the PR3 row: the act-phase loop + 3 first-party grants + boot assertion shipped, proven by fixtures/integration; the 2 strict-xfail conversions + #347 blockers explicitly deferred to PR4 (live-caller readiness) per the Option-A reconciliation. Keep it factual — no decision reversal.

- [ ] **Step 2: Run the FULL unit suite (line-pinned audit AST guard)**

Run: `uv run pytest tests/unit -q`
Expected: PASS — including `tests/unit/audit/test_audit_log_result_domain_closed.py`. If the new `orchestrator.turn` `result` values (`budget_blocked`, `max_iterations_reached`, `provider_failed`, `success`, `budget_overrun`) trip a closed-vocab/AST guard, register any genuinely-new dynamic `result=<var>` site per that test's `expected` list. (The loop reuses existing `orchestrator.turn` result tokens; `max_iterations_reached` is the one to check against `ck_audit_log_result` — if it is not already in the domain, either reuse an existing token or add it via the documented migration/guard-registration path and NOTE it for the security reviewer.)

- [ ] **Step 3: Run the adversarial suite (release-blocking — Task 4 touched security/)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS — the 2 deferred xfails remain XFAIL (green); no capability-bypass regression from the new grants.

- [ ] **Step 4: Run integration + i18n + full quality gate**

Run: `uv run pytest tests/integration/orchestrator -q && uv run pybabel compile -d locale -D alfred --statistics && make check`
Expected: green (`make check` = lint + format + type + test; verify `$?`, not a `tail`-masked pipe).

- [ ] **Step 5: Commit docs + finalize**

```bash
git add docs/superpowers/specs/2026-07-05-issue-339-llm-tool-calling-design.md docs/subsystems/security.md
git commit -m "docs(339): mark PR3 act-phase loop shipped; note PR4 deferrals (#339 PR3)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

- [ ] **Step 6: Update project memory**

Via `~/.claude/memory/bin/memory-write`, append a PR3-implemented section to `procedural_339_tool_calling_design.md` (what shipped, the Option-A scope decision + PR4 deferrals, the phase-index audit-convention change, the axis-faithful boot assertion, any TDD lessons). Update `MEMORY.md`'s Current-state bullet.

---

## Self-review

**1. Spec coverage (§6/§7/§9/§10/§11 PR3 row):**

- §6 loop (parse tool_use → ordered dispatch → feed back → re-complete): Tasks 2+3. ✓
- §6 deterministic order, never `gather`, monotonic `call_index`: Task 3 (`test_two_tool_turn_dispatches_in_order`). ✓
- §6 in-turn tool messages ephemeral + negative-persistence test: Task 3 (`test_tool_results_never_persist_to_episodic`). ✓
- §6 failure classification (canary escalate vs recoverable): delegated to the merged `dispatch_tool`; loop leaves escalations uncaught (Task 3 escalation note). ✓
- §6 deadline reconciliation (core-004): resolved by the pre-existing `DeadlineWrapper` wrap; `max_iterations` is the backstop (Task 2 comment + `loop_constants`). ✓
- §7 per-iteration budget pre-check + `max_iterations` + `MAX_TOOL_CALLS_PER_ITERATION` + per-turn accumulator + charge-raise force-record (mem-002): Task 2 (pre-check, force-record, accumulator) + Task 3 (fan-out cap). ✓
- §7 provider_failed per-iteration audit arm (core-003): Task 2 (indexed `provider_call:{iteration}` arm). ✓
- §9 stop conditions (stop_reason, max_iterations, fan-out, empty tool_calls treated as end): Task 2 (`stop_reason != "tool_use" or not tool_calls`) + Task 3. ✓
- §10 audit every completion + dispatch, indexed `subject.phase`, named hookpoint, `t()` strings, DLP on extracted T2: completions Task 2/3; dispatch rows + hookpoint + DLP in the merged `dispatch_tool`; loop `t()` messages Task 3. ✓
- §11 PR3 "integration tests proving a 2-tool turn (one egress + one internal) + budget-refusal + negative-persistence": Task 5 (real chain) + Task 3 (budget mid-turn break, negative-persistence). ✓
- HARD deliverable (3 grants + boot assertion): Task 4. ✓
- Deferred (xfails + #347): documented in Scope Reconciliation → PR4. Flagged for veto.

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N". Two intentional reuse-pointers (Task 2 `WorkingMemory`/`TaggedContent` driver, Task 5 loopback fixtures) explicitly say "copy the proven shape from `test_core.py` / `test_tool_assembly.py`" rather than re-deriving — that is DRY, not a placeholder; the source files are named exactly.

**3. Type consistency:** `dispatch_tool` call in Task 3 matches the merged signature (positional `call, call_index`; keyword `ctx/registry/gate/dlp/audit/user_id/correlation_id/language`). `Message(role="tool", tool_call_id=..., content=...)` satisfies the PR1 validator. `TurnEgressContext(adapter_id, inbound_id, session_id)` matches. Grant field names (`plugin_id/subscriber_tier/hookpoint/content_tier/proposal_branch`) match `GrantRow`. `_first_party_grant_live` uses `check` vs `check_content_clearance` per the verified axis semantics. `final_response`/`final_charge_result`/`per_turn_spent_usd` bindings are consistent across Tasks 2-3.

---

## Execution handoff

Recommended: **subagent-driven-development** (fresh subagent per task + two-stage review), given the security-sensitive Task 4 (grant seed → security sign-off) and the trust-boundary loop. Tasks are ordered so each ends with an independently-testable deliverable; Task 4 is independent of Tasks 1-3 and can run in parallel if desired, but Task 5 depends on Tasks 1-4 and Task 6 gates on all.
