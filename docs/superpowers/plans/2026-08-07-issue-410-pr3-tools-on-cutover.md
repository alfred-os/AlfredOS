# #410 PR3 — Tools-on cutover (clock.now only) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisites: PR1 and PR2 must both be merged first** (found during
`/review-plan` — neither prior plan stated this explicitly, though both are
self-consistent once verified). Task 1's `build_orchestrator` widening
inserts `tool_registry`/`gate`/`outbound_dlp` alongside PR1's
`side_effect_ledger` and PR2's `replay_journal` params, which must already
exist on `main`.

**Goal:** Make the live comms turn (Discord + `alfred chat`) able to **act**, not just converse — the first genuinely live, working tool call on the comms path. Ships `clock.now` only. **`web.fetch` is deliberately NOT activated in this PR** — see Context below.

**Architecture:** Widen `build_orchestrator` to accept the `(tool_registry, gate, outbound_dlp)` trio (currently always `None`), and wire a `ToolRegistry([build_clock_tool(now=...)])` — NOT `build_tool_registry`, which always builds `web.fetch` too — into the live daemon comms boot graph, reusing the `real_gate` and `outbound_dlp` already constructed there. This makes `core.py:973`'s all-three-or-none dispatch-seams guard reachable for the first time. **This PR also closes a dormant CLAUDE.md hard-rule-#4 gap in `tool_dispatch.py`'s `InternalToolSpec` branch (Task 2a)** — pre-existing since #339, but only reachable in production once this PR wires `clock.now` live, and squarely within the `alfred-security-engineer` sign-off this PR already requires as the comms path's first live tool dispatch.

**Resolved by a PR1 design correction, recorded here for anyone reading this plan against an earlier draft:** this PR's original Architecture line claimed PR1's `side_effect_ledger`/`tool_registry` construction-time guard became an "obligation this PR must discharge." A `/review-plan` fleet pass found that combination would make the daemon fail to boot the instant this PR's Task 2 wired a real `tool_registry` alongside PR1's `side_effect_ledger` — four reviewers independently traced the same crash. The actual fix landed in PR1, not here: PR1 no longer gates the budget charge at all (the thing that guard was protecting), so the guard was dropped from the plan before any implementation — PR1's Task 4 never adds it (there is no shipped code to find or delete; this is plan-draft history, not a code change). This PR does not need to touch, satisfy, or work around any such guard — `Orchestrator.__init__` accepts `side_effect_ledger` and `tool_registry` together with no special interaction.

**Tech Stack:** Python 3.14, pytest + pytest-asyncio, testcontainers (Postgres), real bwrap quarantine child (echo double in tests, matching every sibling integration test in this tree).

## Context — why `clock.now` only

The original design assumed this PR would call `build_tool_registry` (`src/alfred/orchestrator/tool_assembly.py:68`), which builds BOTH `web.fetch` and `clock.now`. Verifying the web-fetch allowlist path before wiring it found a real, previously-unknown blocker:

- `src/alfred/cli/web.py:69` `_list_allowlist_entries()` **unconditionally returns `[]`** — its own docstring: "until PR-S3-7 wires the Postgres `web_allowlist` projection." That work does not exist yet, and is not tracked as an issue anywhere (Task 6 files one).
- `AllowlistIntersection` (`src/alfred/plugins/web_fetch/allowlist.py:167`) is a TRUE `manifest ∩ operator ∩ session` intersection — "the session never widens the surface." An always-empty operator side makes the intersection **permanently empty**, so `web.fetch` would be unconditionally denied in production no matter how correctly everything else is wired.
- Shipping `web.fetch` wired-but-permanently-denied was considered and rejected — indistinguishable from a bug to a reader or reviewer.

`clock.now` needs none of this — `build_clock_tool(*, now: Callable[[], datetime]) -> InternalToolSpec` (`src/alfred/orchestrator/builtin_tools.py:33`) has no broker, no egress, no allowlist, no rate limiter, no handle cap. This PR constructs `ToolRegistry([build_clock_tool(...)])` directly, sidestepping `build_tool_registry` entirely — which also makes the one-broker-instance invariant (ADR-0048, between `outbound_dlp`'s broker and `build_tool_registry`'s `broker` param) fully moot for THIS PR; it is fully researched and documented as a forward-note for whichever PR later activates `web.fetch` (Task 6).

## Global Constraints

- `mypy --strict` + `pyright` clean on every new/modified file.
- CLAUDE.md hard rule #7: the dispatch-seams guard (`core.py:973`) stays a loud `raise`, never an `assert`.
- Dual-LLM boundary touched (the comms path's first live tool dispatch) — `alfred-security-engineer` sign-off, the full adversarial suite, and explicit 100% line+branch coverage on the boundary translator are release-blocking, per CLAUDE.md.
- Conventional Commits. No `--no-verify`. `make check` before every push.
- This PR does NOT touch `src/alfred/plugins/web_fetch/`, `build_tool_registry`, or `build_web_fetch_egress_extractor` — those stay exactly as PR2's Task 5 left the boot graph (constructed dark, unreachable).

---

### Task 1: Widen `build_orchestrator` for the tool-dispatch trio

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py:459-517` (`build_orchestrator`)
- Test: `tests/unit/cli/test_bootstrap_build_orchestrator.py` (created by PR1 Task 5)

**Interfaces:**

- Produces: `build_orchestrator(..., tool_registry: ToolRegistry | None = None, gate: CapabilityGate | None = None, outbound_dlp: OutboundDlpProtocol | None = None)`, forwarded to `Orchestrator(...)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/cli/test_bootstrap_build_orchestrator.py`:

```python
async def test_build_orchestrator_forwards_tool_dispatch_trio(monkeypatch: Any) -> None:
    # Deliberately a PLAIN MagicMock, not MagicMock(spec=Settings): pydantic
    # v2 model fields are not plain class attributes, so a spec'd mock does
    # not know about them and raises AttributeError the instant
    # build_budget_guard (called inside build_orchestrator) reads
    # settings.per_call_max_usd. Same fix as PR1/PR2's equivalent tests in
    # this file — see test_build_orchestrator_forwards_side_effect_ledger.
    settings = MagicMock()
    tool_registry = MagicMock()
    gate = MagicMock()
    outbound_dlp = MagicMock()

    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    broker = MagicMock()
    router = MagicMock()
    resolver = MagicMock()
    resolver.version_counter = 1

    orch = build_orchestrator(
        settings,
        broker=broker,
        router=router,
        resolver=resolver,
        session_scope=_scope,
        tool_registry=tool_registry,
        gate=gate,
        outbound_dlp=outbound_dlp,
    )
    assert orch._tool_registry is tool_registry  # type: ignore[attr-defined]
    assert orch._gate is gate  # type: ignore[attr-defined]
    assert orch._outbound_dlp is outbound_dlp  # type: ignore[attr-defined]


async def test_build_orchestrator_defaults_tool_dispatch_trio_to_none() -> None:
    # Regression pin: every caller before this PR omits the trio and gets the
    # exact pre-#410-PR3 unwired state.
    # Deliberately a PLAIN MagicMock, not MagicMock(spec=Settings) — same
    # build_budget_guard/settings.per_call_max_usd AttributeError as above.
    settings = MagicMock()

    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    orch = build_orchestrator(
        settings,
        broker=MagicMock(),
        router=MagicMock(),
        resolver=_resolver_with_version_counter(),
        session_scope=_scope,
    )
    assert orch._tool_registry is None  # type: ignore[attr-defined]
    assert orch._gate is None  # type: ignore[attr-defined]
    assert orch._outbound_dlp is None  # type: ignore[attr-defined]
```

(`_resolver_with_version_counter()` is a small local helper — check whether PR1/PR2's tests in this same file already define an equivalent `resolver` fixture and reuse it rather than duplicating; if not, a one-line `MagicMock()` with `.version_counter = 1` set, matching the pattern already used in this file's other tests, is sufficient.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v -k tool_dispatch_trio`
Expected: FAIL — `TypeError: build_orchestrator() got an unexpected keyword argument 'tool_registry'`

- [ ] **Step 3: Widen the signature**

In `src/alfred/cli/_bootstrap.py`, add imports:

```python
from alfred.hooks.capability import CapabilityGate
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.security.dlp import OutboundDlpProtocol
```

(Check first whether any of these three are already imported in this file under a different alias or `TYPE_CHECKING` block — several sibling modules already import `CapabilityGate`/`OutboundDlpProtocol` for type annotations; do not introduce a duplicate import if one already exists.)

Widen the signature (after PR2's `replay_journal` param) and forward the trio:

```python
        replay_journal: ReplayJournal | None = None,
        # #410 PR3: the tool-dispatch trio. All three additive + optional;
        # `None` (every caller before this PR's Task 2 wiring) preserves
        # today's unwired behaviour exactly — core.py:973's all-three-or-none
        # guard stays unreachable for any partial combination.
        tool_registry: ToolRegistry | None = None,
        gate: CapabilityGate | None = None,
        outbound_dlp: OutboundDlpProtocol | None = None,
    ) -> Orchestrator:
```

And in the `return Orchestrator(...)` call, add `tool_registry=tool_registry, gate=gate, outbound_dlp=outbound_dlp,` alongside the existing `replay_journal=replay_journal,` line.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v`
Expected: PASS (every test in the file, including PR1's and PR2's)

- [ ] **Step 5: Type-check**

Run: `uv run mypy src/alfred/cli/_bootstrap.py tests/unit/cli/test_bootstrap_build_orchestrator.py && uv run pyright src/alfred/cli/_bootstrap.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/_bootstrap.py tests/unit/cli/test_bootstrap_build_orchestrator.py
git commit -m "feat(cli): widen build_orchestrator for the tool-dispatch trio (#410 PR3)"
```

---

### Task 2: Wire `clock.now` into the live boot graph

**Files:**

- Modify: `src/alfred/cli/daemon/_comms_boot.py:747-816` (the forward-instructions region + the `build_orchestrator` call)

- [ ] **Step 1: Replace the stale forward-instructions comment**

The current comment block (added by #338 PR2, describing calling `build_web_fetch_egress_extractor` + `build_tool_registry` "at the point it first needs a live `web.fetch`") is now inaccurate — this PR deliberately does NOT call either. Replace:

```python
        # ── #339 SEAM (G7-2.5 PR2 / §5.3) ───────────────────────────────────
        # The live ``web.fetch`` egress extractor is assembled by
        # ``alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor``,
        # REUSING this same ``extractor`` + ``recorder`` (and the boot
        # ``CapabilityGate``) — it must NOT spawn a second quarantined child
        # (§4.3 one production extractor; CORE-4 shared-child HoL). The factory
        # is NOT called here: ``dispatch_web_fetch`` has zero production callers
        # until #339 wires the tool-calling loop (after G7-3), so building it at
        # boot would be dangling, never-exercised construction. #339 calls the
        # factory at the point it first needs a live ``web.fetch``, threading:
        #   build_web_fetch_egress_extractor(
        #       settings=settings, gate=<the boot CapabilityGate>,
        #       extractor=extractor, recorder=recorder, outbound_dlp=<cast>,
        #       audit_writer=audit,
        #       session_scope=build_boot_session_scope(settings))
        # The gateway relay address rides ``settings.egress_relay_url`` (PR2
        # compose). An integration test over a loopback relay proves the wiring
        # (test_web_fetch_assembly.py), per ADR-0041.
        #
        # SINGLETON CONTRACT (#339): the live caller MUST build the extractor ONCE
        # here at composition and reuse that single instance — do NOT call
        # build_web_fetch_egress_extractor per fetch. RelayEgressClient's in-flight
        # concurrency semaphore is PER-INSTANCE, so a per-fetch factory call would
        # give each fire its own semaphore and defeat the global cap (the "a burst
        # cannot head-of-line the comms relay" guarantee).
        # ────────────────────────────────────────────────────────────────────
```

with:

```python
        # ── #410 PR3: clock.now only — web.fetch is DEFERRED ───────────────
        # build_tool_registry (src/alfred/orchestrator/tool_assembly.py) would
        # build BOTH web.fetch and clock.now, but web.fetch's operator-
        # allowlist read side (alfred.cli.web._list_allowlist_entries) is an
        # unfinished stub that unconditionally returns [] — AllowlistIntersection
        # is a TRUE manifest ∩ operator ∩ session intersection, so an always-
        # empty operator side makes web.fetch PERMANENTLY denied in production
        # regardless of wiring. Shipping it wired-but-denied was rejected as
        # indistinguishable from a bug. This PR constructs a minimal registry
        # directly instead of calling build_tool_registry, sidestepping the
        # web-fetch assembly (build_web_fetch_egress_extractor,
        # RateLimiter/HandleCap/FetchDispatchConfig, the ADR-0048 one-broker-
        # instance invariant) entirely — all of it is deferred to the
        # unauthenticated-web.fetch-activation follow-up, tracked separately.
        # ────────────────────────────────────────────────────────────────────
        tool_registry = ToolRegistry([build_clock_tool(now=lambda: datetime.now(UTC))])
```

Add the imports at the top of the file:

```python
from datetime import UTC, datetime

from alfred.orchestrator.builtin_tools import build_clock_tool
from alfred.orchestrator.tool_registry import ToolRegistry
```

(Check whether `datetime`/`UTC` are already imported in this module under `TYPE_CHECKING` or elsewhere before adding a duplicate.)

- [ ] **Step 2: Wire the trio into the live `build_orchestrator` call**

Replace the `orchestrator = build_orchestrator(...)` call's closing (PR1 added `side_effect_ledger=...`, PR2 added `replay_journal=...`):

```python
            side_effect_ledger=PostgresTurnSideEffectLedger(
                session_scope=build_boot_session_scope(settings)
            ),
            replay_journal=PostgresReplayJournal(
                session_scope=build_boot_session_scope(settings)
            ),
            # #410 PR3: the LIVE trio. `gate` and `outbound_dlp` are the SAME
            # already-constructed boot instances every other component here
            # reuses (real_gate / outbound_dlp params of this function) — no
            # new construction, no new broker, matching CLAUDE.md's "one
            # production extractor, no throwaway construction" discipline.
            tool_registry=tool_registry,
            gate=real_gate,
            outbound_dlp=cast("OutboundDlp", outbound_dlp),
        )
```

- [ ] **Step 3: Type-check**

Run: `uv run mypy src/alfred/cli/daemon/_comms_boot.py && uv run pyright src/alfred/cli/daemon/_comms_boot.py`
Expected: no errors

- [ ] **Step 4: Run the existing boot-graph integration suite**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py -v`
Expected: every PRE-EXISTING test still passes. None of them exercise a tool call today, so none should change behaviour yet — Task 4 adds the first test that does.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py
git commit -m "feat(cli): wire clock.now into the live comms boot graph (#410 PR3)"
```

---

### Task 2a: Close the `InternalToolSpec` DLP-skip gap (found during `/review-plan` pass 2, 2026-08-07)

**Files:**

- Modify: `src/alfred/orchestrator/tool_dispatch.py` (the `InternalToolSpec` branch)
- Modify: `tests/unit/orchestrator/test_tool_dispatch.py`

**Context:** CLAUDE.md hard rule #4 — "DLP is on by default and cannot be disabled per-call. Pure-internal tools can declare 'no DLP needed' once in their manifest and the test suite verifies the claim." `dispatch_tool`'s `InternalToolSpec` branch (pre-existing since #339, already on `main`) never calls `dlp.scan()` at all — the `dlp` parameter it receives is simply unused on that leg — and no manifest field or test anywhere declares/verifies a DLP exemption for it. This branch has been unreachable in production until Task 2 wires `clock.now` live, so the gap has been dormant; it becomes real the moment this PR ships. Fix: mirror the `ExternalToolSpec` leg's existing `dlp.scan()` pattern (scoped try/except `OutboundCanaryTripped`, escalate + a `dlp_canary`/`quarantined` audit row on trip) on the internal leg too — the cheapest fix that closes the gap for `clock.now` and every future `InternalToolSpec` tool automatically, per the security-engineer's suggested action.

The existing `test_internal_tool_dispatches_directly` uses `_NoopDlp()` (an identity passthrough) — it will keep passing whether or not `dlp.scan()` actually runs on this branch, so it cannot prove this fix. A new canary-trip test, mirroring the existing `test_dlp_canary_on_extracted_t2_escalates` for the `ExternalToolSpec` leg, is required to pin the behaviour.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/orchestrator/test_tool_dispatch.py`, near `test_internal_tool_dispatches_directly`:

```python
async def test_internal_tool_dlp_canary_escalates() -> None:
    """The InternalToolSpec leg scans its T2 result too (#410 PR3 — was previously unscanned)."""
    writer = _CapturingAuditWriter()
    with pytest.raises(OutboundCanaryTripped):
        await _dispatch(
            ToolCall(id="1", name="clock.now", arguments={}),
            _int_spec(),
            gate=make_tool_dispatch_gate(),
            dlp=_CanaryDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "dlp_canary"
    assert writer.rows[-1]["subject"]["result_tier"] == "T2"
    assert writer.rows[-1]["result"] == "quarantined"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/orchestrator/test_tool_dispatch.py -v -k internal_tool_dlp_canary`
Expected: FAIL — `OutboundCanaryTripped` is never raised; nothing on the `InternalToolSpec` branch calls `dlp.scan()` yet.

- [ ] **Step 3: Add the `dlp.scan()` call**

In `src/alfred/orchestrator/tool_dispatch.py`, the `InternalToolSpec` branch currently reads (verify against the live file first — do not assume line numbers, only the shape):

```python
    if isinstance(spec, InternalToolSpec):
        try:
            content = await spec.dispatch(invocation)
        except Exception:
            # sec-003 totality (mirrors the external T3 arm): an internal tool
            # raising must NOT escape the chokepoint unaudited (HARD #7).
            await _audit(
                dispatch_outcome="unexpected_error",
                result="fault",
                tool_name=spec.name,
                result_tier="T2",
            )
            raise
        await _audit(
            dispatch_outcome="dispatched", result="success", tool_name=spec.name, result_tier="T2"
        )
        return content
```

Replace the final `await _audit(...); return content` pair with a scoped DLP scan, leaving the existing `except Exception` totality arm above it untouched:

```python
    if isinstance(spec, InternalToolSpec):
        try:
            content = await spec.dispatch(invocation)
        except Exception:
            # sec-003 totality (mirrors the external T3 arm): an internal tool
            # raising must NOT escape the chokepoint unaudited (HARD #7).
            await _audit(
                dispatch_outcome="unexpected_error",
                result="fault",
                tool_name=spec.name,
                result_tier="T2",
            )
            raise
        # #410 PR3 (found during `/review-plan` pass 2, 2026-08-07): CLAUDE.md
        # hard rule #4 requires every outbound path be DLP-scanned by default
        # or carry a declared, test-verified exemption — this leg had
        # neither. Mirror the ExternalToolSpec leg's scoped dlp.scan() +
        # escalate-on-canary pattern below.
        try:
            clean = dlp.scan(content)
        except OutboundCanaryTripped:
            await _audit(
                dispatch_outcome="dlp_canary",
                result="quarantined",
                tool_name=spec.name,
                result_tier="T2",
            )
            raise  # ESCALATE — a canary in an internal tool's T2 is a serious leak.
        await _audit(
            dispatch_outcome="dispatched", result="success", tool_name=spec.name, result_tier="T2"
        )
        return clean
```

- [ ] **Step 4: Run to verify both the new and existing tests pass**

Run: `uv run pytest tests/unit/orchestrator/test_tool_dispatch.py -v`
Expected: PASS — including the pre-existing `test_internal_tool_dispatches_directly` (its `_NoopDlp()` fixture is an identity passthrough, so `content` and `clean` are byte-identical and the assertion `out == "13:00Z"` still holds).

- [ ] **Step 5: Coverage + type-check**

Run: `uv run pytest tests/unit/orchestrator/test_tool_dispatch.py --cov=src/alfred/orchestrator/tool_dispatch --cov-report=term-missing -v`
Expected: 100% line + branch on `tool_dispatch.py` (CLAUDE.md hard rule: trust-boundary code, no exceptions) — the new canary-trip arm must show as covered, not just the happy path.

Run: `uv run mypy src/alfred/orchestrator/tool_dispatch.py && uv run pyright src/alfred/orchestrator/tool_dispatch.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/orchestrator/tool_dispatch.py tests/unit/orchestrator/test_tool_dispatch.py
git commit -m "fix(security): scan InternalToolSpec dispatch results through DLP (#410 PR3)"
```

---

### Task 3: Positive test for the dispatch-seams guard

**Files:**

- Modify: `tests/unit/orchestrator/test_act_loop.py` (`test_constructor_defaults_tool_seams_to_none` already covers the negative all-`None` case; this adds the positive all-wired case)

The existing `core.py:973` guard (`if self._tool_registry is None or self._gate is None or self._outbound_dlp is None: raise ...`) has only ever been exercised with all three `None` (the pre-#410 state) or, via `test_act_loop.py`'s `TestActLoopOrderedDispatch`, all three wired via `_make_orchestrator(..., tool_registry=..., gate=..., outbound_dlp=...)` — but that test never asserts the GUARD ITSELF is bypassed correctly; it asserts dispatch behaviour. Add an explicit, minimal test naming the guard.

- [ ] **Step 1: Write the test**

```python
async def test_dispatch_seams_guard_is_bypassed_when_all_three_wired(
    monkeypatch: Any,
) -> None:
    """core.py:973's all-three-or-none guard never fires when genuinely all three are set."""
    r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
    r1 = _text_response("the time is now")
    router = MagicMock()
    router.complete = AsyncMock(side_effect=[r0, r1])

    async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
        return "2026-08-07T00:00:00+00:00"

    monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
    orch = _make_orchestrator(
        router=router,
        budget=_make_no_op_budget(),
        tool_registry=_fake_registry("clock.now"),
        gate=MagicMock(),
        outbound_dlp=MagicMock(),
    )
    reply = await _drive_turn(orch)
    assert reply == "the time is now"
```

- [ ] **Step 2: Run to verify it passes**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v -k dispatch_seams_guard_is_bypassed`
Expected: PASS (this is a regression pin, not new behaviour — `dispatch_tool` was already reachable in unit tests via direct construction; this PR's news is that PRODUCTION now reaches it too, proven in Task 4)

- [ ] **Step 3: Commit**

```bash
git add tests/unit/orchestrator/test_act_loop.py
git commit -m "test(orchestrator): pin the dispatch-seams guard's positive (all-wired) case (#410 PR3)"
```

---

### Task 4: Integration test — a real inbound message drives a real `clock.now` dispatch

**Files:**

- Modify: `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` (add a new test near the HARD#5 provenance test)

**Release-blocking** — CLAUDE.md's dual-LLM-boundary rule: this is the comms path's first live tool dispatch.

- [ ] **Step 0: Extend the shared gate fixture with a `tool.dispatch` grant**

**Critical, found during `/review-plan` (2026-08-07):** `_boot_stack`'s gate fixture (`_boot_gate(grant_downgrade=...)`, this same file) does not seed a `tool.dispatch` capability grant — it predates #410 and only every needed the downgrade + DLP-subscriber grants. `dispatch_tool` (`src/alfred/orchestrator/tool_dispatch.py`) calls `gate.check(plugin_id="alfred.orchestrator.tool_dispatch", hookpoint="tool.dispatch", requested_tier="system")` before dispatching anything, and `GatePolicy.check()` fails CLOSED on any unmatched grant (`src/alfred/security/capability_gate/policy.py`). Without this grant, Task 4's flagship test would silently exercise the gate-**denied** branch, not the success path it claims to prove — and nothing in the test as drafted would catch that (the router double ignores tool-result content and returns its fixed answer regardless).

Read `_boot_gate()`'s current body in this file, and `tests.helpers.gates.make_tool_dispatch_gate()` (the fixture this codebase already has for exactly this grant — used by `tests/integration/orchestrator/conftest.py`'s `_assembly_gate()`, which composes it onto ONE real `RealGate` alongside other grants, the established pattern to follow here). Extend `_boot_gate()` to ALSO seed the `tool.dispatch` grant `make_tool_dispatch_gate()` provides, composed onto the same `RealGate` instance `_boot_gate()` already returns — never a second gate object, and never a permissive shim (CLAUDE.md hard rule #2). This is additive: every existing test in this file that doesn't dispatch tools is unaffected by one more grant existing on the gate.

- [ ] **Step 1: Add a tool-call-then-answer router double**

`FixedAnswerRouter` (`tests/helpers/routers.py:23`) always returns ONE fixed text answer (`stop_reason="end_turn"`) — it cannot express a tool-use response as-is. `_boot_stack`'s `router` param is typed as the CONCRETE class `FixedAnswerRouter | None` (not a Protocol), matching this module's existing `_CapturingRouter(FixedAnswerRouter)` — so the new double must SUBCLASS `FixedAnswerRouter` too (found during `/review-plan`: an earlier draft used a bare duck-typed class here, which fails `mypy --strict` against `_boot_stack`'s real signature). Add near this module's other router doubles:

```python
class _ToolCallThenAnswerRouter(FixedAnswerRouter):
    """Requests ONE tool call on the first completion, answers (the
    inherited fixed ``self.answer``) on the second.

    Subclasses ``FixedAnswerRouter`` — required by ``_boot_stack``'s
    concrete `FixedAnswerRouter | None` typing, matching this module's
    existing ``_CapturingRouter(FixedAnswerRouter)`` precedent — rather than
    a bare duck-typed double.
    """

    def __init__(self, *, tool_name: str, answer: str) -> None:
        super().__init__(answer=answer)
        self._tool_name = tool_name

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.requests.append(request)
        if len(self.requests) == 1:
            return CompletionResponse(
                content="",
                tokens_in=1,
                tokens_out=1,
                cost_usd=0.0,
                model="tool-call-then-answer-test-double",
                stop_reason="tool_use",
                tool_calls=(ToolCall(id="tc-1", name=self._tool_name, arguments={}),),
            )
        return CompletionResponse(
            content=self.answer,
            tokens_in=1,
            tokens_out=1,
            cost_usd=0.0,
            model="tool-call-then-answer-test-double",
            stop_reason="end_turn",
            tool_calls=(),
        )
```

Add the import: `from alfred.providers.base import ToolCall` (check whether this module already imports `ToolCall` before adding a duplicate — `CompletionRequest`/`CompletionResponse` are already imported per this file's existing `_all_message_text` helper).

- [ ] **Step 2: Write the test**

```python
async def test_real_inbound_message_dispatches_a_real_clock_now_tool_call(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#410 PR3: the comms path's first live tool dispatch, end-to-end.

    A real inbound message, over the real boot graph (real Postgres, real
    echo quarantine child, real WorkingMemoryPool, real audit log), drives a
    completion that requests clock.now, dispatches it for real through
    dispatch_tool -> ToolRegistry -> InternalToolSpec, feeds the result back,
    and produces a final answer.
    """
    tool_call_router = _ToolCallThenAnswerRouter(tool_name="clock.now", answer="the time is now")
    async with _boot_stack(postgres_url, monkeypatch, router=tool_call_router) as stack:
        await stack.send_inbound(body={"text": "what time is it"})

        assert len(stack.captured_router.requests) == 2  # planner call, then wrap-up
        sent_replies = stack.sender.sent
        assert len(sent_replies) == 1
        assert "the time is now" in sent_replies[0].body[0]

        # tool.dispatch audit row fired for the real dispatch.
        rows = stack.audit_rows(event="tool.dispatch")
        assert len(rows) == 1
        assert rows[0]["subject"]["tool_name"] == "clock.now"
        # Non-vacuous guard (found during /review-plan): without this, a
        # regression to the gate-DENIED branch (the SPECIFIC failure mode
        # Step 0 exists to prevent — clock.now IS registered, so a gate
        # denial produces a DIFFERENT dispatch_outcome than "unknown_tool",
        # e.g. something like "capability_denied" — verify the exact
        # literal against src/alfred/orchestrator/tool_dispatch.py's real
        # gate-check failure branch, do not guess) would pass this test
        # silently, since the router double answers regardless of tool
        # result content. Assert the SUCCESS-path dispatch_outcome/result
        # POSITIVELY (read the real values dispatch_tool's happy path
        # writes), not just "not a known failure string" — a positive
        # assertion is the only one that can't be satisfied by an
        # unanticipated third failure mode.
        assert rows[0]["subject"]["dispatch_outcome"] == "dispatched"  # verify against real source
        assert rows[0]["result"] == "success"  # verify against real source
```

- [ ] **Step 3: Run to verify it passes**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v -k clock_now`
Expected: PASS

- [ ] **Step 4: Run the full module (regression check)**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v`
Expected: PASS — every pre-existing test (including PR1's Task 6/7 replay-safety tests) still green.

- [ ] **Step 5: Confirm release-blocking coverage**

**Found during `/review-plan`:** the original invocation here targeted `tests/unit/orchestrator/tool_dispatch.py`, which does not exist (the real test file is `tests/unit/orchestrator/test_tool_dispatch.py`; the module under test is the SOURCE file `src/alfred/orchestrator/tool_dispatch.py`). This coverage is also NOT new work this PR introduces — CI already enforces a 100% gate on `tool_dispatch.py` via `make coverage-gates` (confirmed against `.github/workflows/ci.yml`, which already tracks this exact file). Run the CANONICAL gate rather than reinventing an ad hoc invocation:

Run: `make coverage-gates` (or whatever this repo's `Makefile` names the target that runs `.github/workflows/ci.yml`'s per-file coverage gates — read the Makefile first to confirm the exact target name before running it)
Expected: PASS — `tool_dispatch.py` was already at 100% before this PR (from #339's own work); this step confirms this PR's new production callers didn't regress it, not that 100% is newly achieved.

- [ ] **Step 6: Extend end-to-end: the existing unknown-tool corpus property, now through the LIVE boot graph**

`tests/adversarial/capability_bypass/test_cap_2026_010_011_dispatch_perimeter_injection.py`
(`test_unknown_tool_refused`, cap-2026-010) already fully covers "an unknown
tool name is refused by `dispatch_tool` at the registry-resolution
perimeter" — but only by calling `dispatch_tool` directly with a bare test
registry, never through a real live turn (nothing called
`build_tool_registry`/wired the trio into production before this PR). A NEW
corpus entry would duplicate that coverage; the genuinely new, non-duplicate
property PR3 introduces is that the SAME already-verified refusal survives
end-to-end through the wiring this PR adds — the planner hallucinating a
tool name that was never registered, on a REAL live turn, over the REAL
boot graph.

Add to `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py`,
reusing Task 4's `_ToolCallThenAnswerRouter` (constructed with a name NOT in
the live registry — `clock.now` is the only tool PR3 wires):

```python
async def test_real_turn_refuses_a_hallucinated_tool_name_end_to_end(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#410 PR3: cap-2026-010's already-corpus-verified refusal
    (test_cap_2026_010_011_dispatch_perimeter_injection.py) survives
    end-to-end through the live boot graph — the first real exercise of
    that property through a genuine live turn rather than a bare
    dispatch_tool call.
    """
    hallucinating_router = _ToolCallThenAnswerRouter(
        tool_name="definitely.not.a.registered.tool", answer="recovered anyway"
    )
    async with _boot_stack(postgres_url, monkeypatch, router=hallucinating_router) as stack:
        await stack.send_inbound(body={"text": "do the impossible thing"})

        # The turn RECOVERS — the planner gets the refusal string back as a
        # tool result and still produces a final answer, never a crash or
        # an escalated turn halt.
        assert len(stack.sender.sent) == 1
        assert "recovered anyway" in stack.sender.sent[0].body[0]

        rows = stack.audit_rows(event="tool.dispatch")
        assert len(rows) == 1
        assert rows[0]["subject"]["dispatch_outcome"] == "unknown_tool"
        assert rows[0]["result"] == "refused"
```

- [ ] **Step 7: Run to verify it passes**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v -k hallucinated_tool_name`
Expected: PASS

- [ ] **Step 8: Run the full adversarial suite (regression — this PR touches no adversarial file, but confirms nothing else broke)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS, release-blocking. `test_cap_2026_010_011_dispatch_perimeter_injection.py::test_unknown_tool_refused` in particular must still pass unmodified — Step 6 above proves the SAME property at a new layer, it does not replace the unit-level proof.

- [ ] **Step 9: Commit**

```bash
git add tests/integration/comms_mcp/test_real_turn_inbound_boundary.py
git commit -m "test(comms): real inbound message drives a real clock.now dispatch + hallucinated-tool refusal, end-to-end (#410 PR3)"
```

---

### Task 5: Amend ADR-0049

**Files:**

- Modify: `docs/adr/0049-real-privileged-turn-comms-inbound.md`

- [ ] **Step 1: Find the empty-registry premise**

**Found during `/review-plan`:** the original grep here (`"empty tool registry\|egress tools DEFERRED\|Scope decision"`) matches nothing against the real file — case mismatch (ADR-0049 capitalizes "Empty tool registry"; "deferred" appears lowercase, line-wrapped) and a non-existent "Scope decision" heading (that heading belongs to the DESIGN SPEC's §3, not this ADR — ADR-0049's real sections are Context/Decision/Consequences/Alternatives/References, per this repo's ADR convention). Use a case-insensitive search instead:

Run: `grep -ni "empty tool registry\|deferred" docs/adr/0049-real-privileged-turn-comms-inbound.md`

- [ ] **Step 2: Add a superseding note**

At the location Step 1 finds (fill in today's actual date at implementation time, not a placeholder), add:

```markdown
> **Superseded in part by #410 PR3.** The "egress tools deferred... empty
> tool registry" premise below no longer holds: the live comms turn now
> dispatches `clock.now` for real. `web.fetch` remains deferred — not for
> the reason below (tool-calling itself), but because its operator-allowlist
> projection is unfinished (see
> `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md` §3 item 6).
> The original text is preserved for historical record.
```

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0049-real-privileged-turn-comms-inbound.md
git commit -m "docs(adr): ADR-0049 — supersede the empty-tool-registry premise (#410 PR3)"
```

---

### Task 6: File the two forward-looking issues

**Files:** none (GitHub issues, not repo files)

- [ ] **Step 1: File the allowlist-projection gap**

```bash
gh issue create --title "web.fetch operator-allowlist projection is unwired (_list_allowlist_entries always returns [])" --body "$(cat <<'EOF'
## Summary

\`src/alfred/cli/web.py:69\` \`_list_allowlist_entries()\` unconditionally
returns \`[]\`. Its own docstring says this is a placeholder "until PR-S3-7
wires the Postgres \`web_allowlist\` projection" — that work was never
tracked as an issue and does not exist.

\`alfred web allowlist add/remove\` write REVIEWER-GATED state.git proposals
(via \`StateGitProposalClient\`) but there is no code path that projects
approved proposals into a queryable store, and \`allowlist list\` /
\`FetchDispatchConfig.operator_allowed_entries\` have nothing to read.

## Impact

\`AllowlistIntersection\` (\`src/alfred/plugins/web_fetch/allowlist.py:167\`)
is a true \`manifest ∩ operator ∩ session\` intersection. An always-empty
operator side makes \`web.fetch\` PERMANENTLY, unconditionally denied — this
blocks web.fetch's activation regardless of how correctly the tool-calling
machinery itself is wired (#410 PR3 shipped \`clock.now\` only because of
this gap).

## Scope

- Design the merged-proposal -> live-projection path (state.git merge hook,
  or a supervisor-side reconciliation pass — needs its own brainstorm).
- Wire \`_list_allowlist_entries()\` to the real query.
- Wire the daemon boot path to construct \`FetchDispatchConfig.operator_allowed_entries\`
  from the same projection.

## Relates to

#410 (found while writing PR3's implementation plan, 2026-08-07); blocks the
unauthenticated-web.fetch-activation follow-up, which itself blocks the
already-deferred authenticated-web.fetch follow-up (ADR-0048 forward gates).
EOF
)"
```

- [ ] **Step 2: File the web.fetch activation follow-up (references the one-broker-instance fix already researched)**

```bash
gh issue create --title "Activate web.fetch on the live comms turn (unauthenticated) — blocked on the allowlist projection" --body "$(cat <<'EOF'
## Summary

#410 PR3 wires \`clock.now\` only. \`web.fetch\` needs, in addition to the
allowlist-projection issue (file that first, this issue depends on it):

## The one-broker-instance invariant (ADR-0048) — already researched, ready to implement

\`_comms_boot.py\` builds its own \`secret_broker = build_broker(settings)\`
locally; \`_commands.py\` separately builds a DIFFERENT broker instance
(inside \`_build_boot_outbound_dlp\`) for \`outbound_dlp\`. \`build_broker\` has
no caching (\`SecretBroker.from_settings\` — a fresh instance every call), so
these are two distinct objects today. \`build_tool_registry\`'s \`broker\` param
and \`outbound_dlp\`'s broker MUST be the same instance (ADR-0048) or a
secrets hot-reload diverges the DLP-scan snapshot from the secret-
substitution snapshot (confused-deputy risk).

**Fix (verified against all 7 call sites, 2026-08-07 — 1 production +
6 integration test files):** make \`broker\`/\`secret_broker\` OPTIONAL params
on \`_build_boot_outbound_dlp\` and \`_build_comms_boot_graph\`
(default: build internally, byte-for-byte unchanged for every existing
caller — zero blast radius on the 6 test files that call either directly).
Have \`_commands.py\`'s ONE production call site build the broker once,
inside the EXISTING \`try/except SecretBrokerConfigError\` around
\`_build_boot_outbound_dlp\`, and pass it to BOTH functions. The redundant
\`except SecretBrokerConfigError\` guard around \`_build_comms_boot_graph\`'s
call (\`_commands.py\` ~line 998, its own comment already says "unreachable
TODAY... defense-in-depth against reordering") should be LEFT AS-IS, not
removed — with the optional-param approach \`_build_comms_boot_graph\` still
has its own internal build-a-broker path for other callers, so that guard is
not fully dead code, just unreachable on this one call site by construction.

## Scope

- Depends on the allowlist-projection issue (file first).
- The broker-sharing fix above.
- Call \`build_tool_registry\` (not a bespoke registry) from \`_comms_boot.py\`,
  replacing PR3's minimal \`ToolRegistry([build_clock_tool(...)])\`.
- \`RateLimiter\`/\`HandleCap\`/\`FetchDispatchConfig\` construction from real
  \`Settings\` — no existing production precedent (only test files construct
  these today); needs its own design pass.

## Relates to

#410 (found while writing PR3, 2026-08-07); the authenticated-fetch
follow-up (ADR-0048 forward gates) should land AFTER this one, not bundled.
EOF
)"
```

- [ ] **Step 3: Cross-reference both new issues from the design spec**

Update `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md`'s §9 "Out of scope" bullets to replace "file one" with the actual issue numbers just created.

---

### Task 7: Manual UAT

**Files:** none (manual verification)

- [ ] **Step 1: Boot the real stack**

Run: `docker compose up -d` (or the equivalent local dev-stack command this repo uses — check `bin/dev-setup.sh` / `README.md` for the canonical form).

- [ ] **Step 2: Send a real Discord message asking for the time**

Via a real Discord DM to the bot (or `alfred chat` if UAT is being done against the TUI path instead — both now reach the same `Orchestrator` with the trio wired), send a message that should trigger a `clock.now` call (e.g. "what time is it right now?").

- [ ] **Step 3: Verify**

- The bot's reply reflects a real timestamp, not a hallucinated one.
- `alfred audit graph --since 1h` (or `alfred audit log`) shows a `tool.dispatch` row for `clock.now` correlated with the turn's `orchestrator.turn` row.
- No error, no refusal, no `dispatch_seams_unwired` string anywhere in `docker compose logs alfred-core --since 1h` (found during `/review-plan`: the original wording here — "no ... in the daemon logs" — named no concrete command; this is it, per this repo's `docker-compose.yaml` service name).

- [ ] **Step 4: Record the UAT result**

Per this repo's standing cadence, note the UAT pass/fail in the PR description before requesting `/review-pr` + CodeRabbit.

---

## Definition of Done

- [ ] All 7 tasks' tests pass: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py tests/unit/orchestrator/test_act_loop.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py tests/adversarial -v`
- [ ] `make check` passes clean.
- [ ] 100% line+branch coverage on `src/alfred/orchestrator/tool_dispatch.py` (dual-LLM boundary, release-blocking).
- [ ] `alfred-security-engineer` sign-off obtained (dual-LLM boundary, first live comms-path tool dispatch).
- [ ] Manual UAT (Task 7) recorded pass.
- [ ] `/review-plan` fleet run on this plan (and PR1's, PR2's) before implementation; full `/review-pr` fleet + CodeRabbit `full review` on the resulting PR before merge.
- [ ] Both forward-looking issues (Task 6) filed and cross-referenced from the design spec.
