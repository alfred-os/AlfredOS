# #410 PR3 — Tools-on cutover (clock.now only) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Re-verified against `main` post-PR1/PR2 merge, 2026-08-11.** PR1 (#579,
> merged 2026-08-11T03:57:27Z) and PR2 are both on `main`; **Prerequisites
> below are satisfied.** The architecture holds — `Orchestrator.__init__`
> already accepts `tool_registry`/`gate`/`outbound_dlp` (from #339, predating
> #410) and `core.py`'s dispatch-seams guard + replay-journal `append_batch`
> integration are live exactly as designed. Two concrete corrections were
> needed and are applied inline below, each marked with a `> **Correction
> (... 2026-08-11)**` callout: (1) `build_orchestrator` does NOT expose
> `side_effect_ledger`/`replay_journal` as caller params — PR1/PR2 construct
> both unconditionally inside it, so the Prerequisites line below ("alongside
> PR1's `side_effect_ledger` and PR2's `replay_journal` params") is
> imprecise — see Task 1; (2) the test file Task 1 targets doesn't exist
> under its original name. Line numbers throughout (originally cited against
> the 2026-08-07 pre-PR1/PR2 tree) have drifted — each has been re-verified
> and either corrected or marked "verify against the live file."
>
> **A full 6-agent `/review-plan` fleet pass (+ coordinator + Phase C
> cross-checks) then ran against the re-verified plan, 2026-08-11.** 15
> findings (0 Critical, 4 High, 8 Medium, 3 Low), all corroborated (6
> cross-reviewer, 9 cross-check-confirmed, 0 disputed/retracted). One was
> BLOCKING: `alfred-security-engineer` withheld sign-off pending Task 2a's
> DLP fix gaining a totality wrapper (sec-001) — now fixed inline below. All
> other findings are also fixed inline, each marked with its own
> `/review-plan` correction callout. A third forward-looking issue (**#584**,
> authenticated `web.fetch`) was filed alongside the two from PR0 bookkeeping.
> This plan is now believed implementation-ready; per the coordinator's own
> recommendation, a fast confirm-only pass (not a full re-review) is
> sufficient before subagent-driven-development begins.

**Prerequisites: PR1 and PR2 must both be merged first** (found during
`/review-plan` — neither prior plan stated this explicitly, though both are
self-consistent once verified). Task 1's `build_orchestrator` widening adds
`tool_registry`/`gate`/`outbound_dlp` as three new params on
`build_orchestrator` — PR1's `side_effect_ledger` and PR2's `replay_journal`
are constructed unconditionally INSIDE that function, not exposed as params
(see Task 1's correction), but the underlying `Orchestrator` class support
for all five must already exist on `main`, which it does.

**Goal:** Make the live comms turn (Discord + `alfred chat`) able to **act**, not just converse — the first genuinely live, working tool call on the comms path. Ships `clock.now` only. **`web.fetch` is deliberately NOT activated in this PR** — see Context below.

**Architecture:** Widen `build_orchestrator` to accept the `(tool_registry, gate, outbound_dlp)` trio (currently always `None`), and wire a `ToolRegistry([build_clock_tool(now=...)])` — NOT `build_tool_registry`, which always builds `web.fetch` too — into the live daemon comms boot graph, reusing the `real_gate` and `outbound_dlp` already constructed there. This makes `core.py`'s all-three-or-none dispatch-seams guard (currently ~`:1364`, verify against the live file — drifted from the original `:973` estimate as PR1/PR2 landed) reachable for the first time. **This PR also closes a dormant CLAUDE.md hard-rule-#4 gap in `tool_dispatch.py`'s `InternalToolSpec` branch (Task 2a)** — pre-existing since #339, but only reachable in production once this PR wires `clock.now` live, and squarely within the `alfred-security-engineer` sign-off this PR already requires as the comms path's first live tool dispatch.

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
- CLAUDE.md hard rule #7: the dispatch-seams guard (`core.py`, ~`:1364` — verify against the live file) stays a loud `raise`, never an `assert`.
- Dual-LLM boundary touched (the comms path's first live tool dispatch) — `alfred-security-engineer` sign-off, the full adversarial suite, and explicit 100% line+branch coverage on the boundary translator are release-blocking, per CLAUDE.md.
- Conventional Commits. No `--no-verify`. `make check` before every push.
- This PR does NOT touch `src/alfred/plugins/web_fetch/`, `build_tool_registry`, or `build_web_fetch_egress_extractor` — those stay exactly as PR2's Task 5 left the boot graph (constructed dark, unreachable).

---

### Task 1: Widen `build_orchestrator` for the tool-dispatch trio

> **Correction (found while re-verifying this plan against `main` post-PR1/PR2
> merge, 2026-08-11):** the file/test-pattern below in the original draft was
> written against an ASSUMED PR1/PR2 shape that shipped differently. Two
> concrete corrections:
>
> 1. `build_orchestrator` does **not** expose `side_effect_ledger` or
>    `replay_journal` as caller-injectable parameters at all — PR1/PR2
>    construct `PostgresTurnSideEffectLedger()` and
>    `PostgresReplayJournal(session_scope=audit_session_scope)`
>    **unconditionally, inline**, inside the `return Orchestrator(...)` call
>    (`src/alfred/cli/_bootstrap.py:570-580`). There is no `replay_journal=`
>    line to add the trio "alongside" — the trio is three genuinely NEW
>    params, full stop.
> 2. The test file `tests/unit/cli/test_bootstrap_build_orchestrator.py`
>    does not exist. PR1/PR2's actual test file for `build_orchestrator` is
>    `tests/unit/cli/test_build_orchestrator_wiring.py`, and it does NOT use
>    the `MagicMock()`-as-`Settings` pattern this draft assumed — it uses a
>    real `Settings()` (via `_base_env(monkeypatch)` setting two env vars)
>    plus `monkeypatch.setattr(_bootstrap, "build_session_scope", ...)` /
>    `monkeypatch.setattr(_bootstrap, "build_budget_guard", ...)`. Follow
>    that file's existing convention below, not the original draft's.

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py` (`build_orchestrator`, currently defined `:487-580` — verify against the live file, do not assume the line number)
- Test: `tests/unit/cli/test_build_orchestrator_wiring.py` (existing file — add to it, do not create a new one)

**Interfaces:**

- Produces: `build_orchestrator(..., tool_registry: ToolRegistry | None = None, gate: CapabilityGate | None = None, outbound_dlp: OutboundDlpProtocol | None = None)`, forwarded to `Orchestrator(...)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/cli/test_build_orchestrator_wiring.py`, following this file's existing `_base_env`/`_stub_resolver`/`_fake_scope` fixtures (defined near the top of the file — reuse them, do not redefine):

```python
def test_forwards_tool_dispatch_trio(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    settings = Settings()
    monkeypatch.setattr(_bootstrap, "build_session_scope", lambda *_a, **_kw: _fake_scope())
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    tool_registry = MagicMock()
    gate = MagicMock()
    outbound_dlp = MagicMock()

    orch = _bootstrap.build_orchestrator(
        settings,
        broker=MagicMock(),
        router=MagicMock(),
        resolver=_stub_resolver(),
        tool_registry=tool_registry,
        gate=gate,
        outbound_dlp=outbound_dlp,
    )
    assert orch._tool_registry is tool_registry
    assert orch._gate is gate
    assert orch._outbound_dlp is outbound_dlp


def test_defaults_tool_dispatch_trio_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression pin: every caller before this PR omits the trio and gets the
    # exact pre-#410-PR3 unwired state.
    _base_env(monkeypatch)
    settings = Settings()
    monkeypatch.setattr(_bootstrap, "build_session_scope", lambda *_a, **_kw: _fake_scope())
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    orch = _bootstrap.build_orchestrator(
        settings, broker=MagicMock(), router=MagicMock(), resolver=_stub_resolver()
    )
    assert orch._tool_registry is None
    assert orch._gate is None
    assert orch._outbound_dlp is None
```

(Check the exact keyword signature `_fake_build_session_scope` uses in this file's existing two tests before assuming `lambda *_a, **_kw` is sufficient — `build_session_scope` is called with a `role=` kwarg the lambda must accept; match the existing tests' monkeypatch signature exactly rather than a bare catch-all if `mypy --strict` complains.)

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding rev-001, High):** the four assertions above deliberately carry NO `# type: ignore[attr-defined]` comments, unlike this same draft's earlier revision. `tool_registry`/`gate`/`outbound_dlp` are typed non-`Any` on `Orchestrator.__init__` and stored verbatim as `self._tool_registry`/etc — accessing them is not a type error, and this repo's `pyproject.toml` sets `warn_unused_ignores = true`. An unnecessary `# type: ignore` on a line mypy doesn't actually flag becomes ITS OWN error (`[unused-ignore]`) under that setting, which would fail this task's own Step 5. This file's existing tests already access equally-private `Orchestrator` attributes (e.g. `orch._side_effect_ledger`, `orch._replay_journal`) with zero ignore comments — follow that established convention.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/cli/test_build_orchestrator_wiring.py -v -k tool_dispatch_trio`
Expected: FAIL — `TypeError: build_orchestrator() got an unexpected keyword argument 'tool_registry'`

- [ ] **Step 3: Widen the signature**

In `src/alfred/cli/_bootstrap.py`, add imports:

```python
from alfred.hooks.capability import CapabilityGate
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.security.dlp import OutboundDlpProtocol
```

(Check first whether any of these three are already imported in this file under a different alias or `TYPE_CHECKING` block — several sibling modules already import `CapabilityGate`/`OutboundDlpProtocol` for type annotations; do not introduce a duplicate import if one already exists.)

Widen the signature — add the trio as three NEW params after `quarantined_extractor` (currently the last param, verify against the live file):

```python
    quarantined_extractor: QuarantinedExtractorLike | None = None,
    # #410 PR3: the tool-dispatch trio. All three additive + optional;
    # `None` (every caller before this PR's Task 2 wiring) preserves
    # today's unwired behaviour exactly — core.py's all-three-or-none guard
    # (currently ~:1364, verify against the live file) stays unreachable for
    # any partial combination.
    tool_registry: ToolRegistry | None = None,
    gate: CapabilityGate | None = None,
    outbound_dlp: OutboundDlpProtocol | None = None,
) -> Orchestrator:
```

And in the `return Orchestrator(...)` call — which already unconditionally constructs `side_effect_ledger=PostgresTurnSideEffectLedger()` and `replay_journal=PostgresReplayJournal(session_scope=audit_session_scope)` (leave those two lines untouched) — add `tool_registry=tool_registry, gate=gate, outbound_dlp=outbound_dlp,` as three additional forwarded lines.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/cli/test_build_orchestrator_wiring.py -v`
Expected: PASS (every test in the file, including PR1's and PR2's two existing tests)

- [ ] **Step 5: Type-check**

Run: `uv run mypy src/alfred/cli/_bootstrap.py tests/unit/cli/test_build_orchestrator_wiring.py && uv run pyright src/alfred/cli/_bootstrap.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/_bootstrap.py tests/unit/cli/test_build_orchestrator_wiring.py
git commit -m "feat(cli): widen build_orchestrator for the tool-dispatch trio (#410 PR3)"
```

---

### Task 2: Wire `clock.now` into the live boot graph

> **Correction (re-verified against `main` post-PR1/PR2 merge, 2026-08-11):**
> the original Step 2 code block below showed `side_effect_ledger=...` and
> `replay_journal=...` lines being ADDED to the `build_orchestrator(...)`
> call. That's now wrong per Task 1's correction: `build_orchestrator`
> constructs both of those unconditionally INSIDE itself — this call site
> already gets them for free and must not pass either explicitly. Only the
> new `tool_registry`/`gate`/`outbound_dlp` lines are added here.

**Files:**

- Modify: `src/alfred/cli/daemon/_comms_boot.py` (the forward-instructions region, currently `:746-771`, + the `build_orchestrator` call, currently `:794-813` — verify against the live file, do not assume line numbers)

- [ ] **Step 1: Replace the stale forward-instructions comment**

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — findings rev-002/sec-002/core-001/comms-001, the single most corroborated finding in the review, independently found by 4 of 6 reviewers, Medium):** this step must replace TWO stale comment blocks, not one. The second — a separate `#338 PR2 cutover` comment a few lines further down (live file, currently `:781-783`), sitting directly above the `router = (...)` assignment right before the `build_orchestrator(...)` call this task's Step 2 modifies — reads: `"Egress tools are DEFERRED (#338 scope): no tool_registry is passed, so the Act loop runs one completion and the (registry, gate, outbound_dlp) trio guard at core.py:973 is never reached."` Both claims in that sentence become false the instant this task's Step 2 lands (`tool_registry` IS now passed; the guard DOES become reachable — this PR's own headline claim), and it already cites the stale `core.py:973` line number. Left uncorrected, it sits at the exact composition site this plan's Definition of Done requires `alfred-security-engineer` sign-off on. Replace it in the same commit, e.g.: `"#410 PR3: the tool-dispatch trio (tool_registry/gate/outbound_dlp) IS now passed below — the (registry, gate, outbound_dlp) trio guard in core.py's Act loop is reachable for the first time on this path."`

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

The existing `orchestrator = build_orchestrator(...)` call (verify its current closing against the live file — it presently ends with `quarantined_extractor=None,`) needs only the trio added; `side_effect_ledger`/`replay_journal` are NOT passed here (Task 1's correction — `build_orchestrator` builds both unconditionally itself):

```python
            # extraction runs at the adapter->bridge boundary, not the orchestrator funnel
            quarantined_extractor=None,
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

- [ ] **Step 4: Run the existing boot-graph integration suite, and add a minimal smoke assertion for the real wiring**

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding test-002, Medium, cross-check confirmed by `alfred-comms-engineer`):** this task is otherwise the only one of Tasks 1/2a/3/4 with no assertion of its own — it wires `clock.now` into the REAL `_comms_boot.py` construction path but proves nothing about that wiring until Task 4, two tasks later. Task 3's guard test does NOT cover this gap either — it drives dispatch through `_make_orchestrator` + a monkeypatched `dispatch_tool`, a different construction path entirely from `_build_comms_boot_graph`. Close the gap cheaply by adding ONE assertion to `tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py` (the exact suite this step already runs, exposing `_CommsBootGraph.inbound_orchestrator`, a `RealTurnOrchestratorAdapter` whose `__init__` stores the constructed `Orchestrator` as `self._orchestrator`):
>
> ```python
> assert "clock.now" in {
>     d.name for d in graph.inbound_orchestrator._orchestrator._tool_registry.definitions()
> }
> ```
>
> This proves the real `_comms_boot.py` wiring actually threads a `clock.now`-bearing registry into the live orchestrator, using infrastructure this step already pays to spin up (real Postgres, real echo quarantine child) — cheaper than duplicating Task 4's integration setup. Scope note: this only covers the `tool_registry` leg, not `gate=real_gate`/`outbound_dlp=cast(...)` identity — that's fine, the full trio's behavioural correctness is still validated by Task 3 (guard bypass) and Task 4 (real dispatch).

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py -v`
Expected: every PRE-EXISTING test still passes, plus the new smoke assertion above. Task 4 still adds the first test that exercises a REAL tool dispatch end-to-end — this step only proves the registry is wired, not that dispatch works.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py
git commit -m "feat(cli): wire clock.now into the live comms boot graph (#410 PR3)"
```

---

### Task 2a: Close the `InternalToolSpec` DLP-skip gap (found during `/review-plan` pass 2, 2026-08-07)

> **BLOCKING correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding sec-001, High, triple-confirmed: originating `alfred-security-engineer` + independent cross-check confirmations from `alfred-core-engineer` and `alfred-test-engineer`). Security sign-off was explicitly withheld pending this fix — do not implement Task 2a's Step 3 as originally drafted below without applying this correction first.**
>
> The originally-drafted Step 3 diff (further down) only wraps `dlp.scan(content)` in `try/except OutboundCanaryTripped` — it has NO totality wrapper for any OTHER exception `dlp.scan()` can raise. `OutboundDlp.scan()` (`src/alfred/security/dlp.py`) is DELIBERATELY DESIGNED to propagate non-canary failures rather than swallow them: a `broker.redact()` bug, DLP's own internal audit-sink callback (documented: "raises propagate per CLAUDE.md hard rule #7"), or a canary-matcher bug. Under the original draft, any such failure on the `InternalToolSpec` leg escapes `dispatch_tool` with **zero audit row** — contradicting the branch's own adjacent sec-003 comment ("an internal tool raising must NOT escape the chokepoint unaudited") and CLAUDE.md hard rule #7. This is exactly the "non-canary DLP fault" class the `ExternalToolSpec` leg's own comment (`tool_dispatch.py:311-317`) already names as something IT defends against, via an `audited`-flag totality wrapper this new code does not mirror. 100% branch coverage (Step 5, as originally drafted) CANNOT catch this — coverage tooling reports on lines/branches present in the file, not an absent `except` clause.
>
> **The fix:** mirror the `ExternalToolSpec` leg's `audited`-flag totality pattern on the `InternalToolSpec` leg too. Step 3's replacement code below has been corrected accordingly; Step 1's test has an added case for the non-canary path.

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


async def test_internal_tool_dlp_non_canary_fault_is_audited() -> None:
    """#410 PR3 (sec-001 correction): a non-canary dlp.scan() failure on the
    InternalToolSpec leg must still leave an audit row before propagating —
    mirrors the ExternalToolSpec leg's existing totality-wrapper test
    (test_non_serializable_downgrade_output_escalates)."""
    writer = _CapturingAuditWriter()

    class _RaisingDlp:
        def scan(self, text: str) -> str:
            raise ValueError("simulated broker.redact bug")

    with pytest.raises(ValueError):
        await _dispatch(
            ToolCall(id="1", name="clock.now", arguments={}),
            _int_spec(),
            gate=make_tool_dispatch_gate(),
            dlp=_RaisingDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "unexpected_error"
    assert writer.rows[-1]["subject"]["result_tier"] == "T2"
    assert writer.rows[-1]["result"] == "fault"
```

(Verify `_RaisingDlp`'s `scan` signature against the live `OutboundDlp`/`OutboundDlpProtocol` contract before implementing — match whatever the real interface expects.)

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

Replace the final `await _audit(...); return content` pair with a scoped DLP scan, leaving the existing `except Exception` totality arm above it untouched. **Corrected per sec-001 (2026-08-11): the DLP-scan region needs its OWN totality wrapper too, mirroring the `ExternalToolSpec` leg's `audited`-flag pattern** — not just a bare `try/except OutboundCanaryTripped`:

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
        # #410 PR3 (found during `/review-plan` pass 2, 2026-08-07; totality
        # wrapper added per `/review-plan` finding sec-001, 2026-08-11):
        # CLAUDE.md hard rule #4 requires every outbound path be DLP-scanned
        # by default or carry a declared, test-verified exemption — this leg
        # had neither. Mirror the ExternalToolSpec leg's `audited`-flag
        # totality pattern (tool_dispatch.py's downgrade+dlp.scan region),
        # not just a bare try/except OutboundCanaryTripped — dlp.scan() is
        # deliberately designed to propagate NON-canary failures too
        # (broker.redact bugs, DLP's own internal audit-sink failures,
        # canary-matcher bugs), and those must not escape unaudited either.
        audited = False
        try:
            try:
                clean = dlp.scan(content)
            except OutboundCanaryTripped:
                await _audit(
                    dispatch_outcome="dlp_canary",
                    result="quarantined",
                    tool_name=spec.name,
                    result_tier="T2",
                )
                audited = True
                raise  # ESCALATE — a canary in an internal tool's T2 is a serious leak.
            await _audit(
                dispatch_outcome="dispatched",
                result="success",
                tool_name=spec.name,
                result_tier="T2",
            )
            return clean
        except Exception:
            # sec-003 totality, again: a non-canary dlp.scan() fault (broker
            # bug, DLP-internal audit-sink failure, canary-matcher bug) must
            # still leave a loud terminal row before propagating.
            if not audited:
                await _audit(
                    dispatch_outcome="unexpected_error",
                    result="fault",
                    tool_name=spec.name,
                    result_tier="T2",
                )
            raise
```

- [ ] **Step 4: Run to verify both new tests (canary AND non-canary) and existing tests pass**

Run: `uv run pytest tests/unit/orchestrator/test_tool_dispatch.py -v`
Expected: PASS — both `test_internal_tool_dlp_canary_escalates` and the corrected-fix's `test_internal_tool_dlp_non_canary_fault_is_audited`, plus the pre-existing `test_internal_tool_dispatches_directly` (its `_NoopDlp()` fixture is an identity passthrough, so `content` and `clean` are byte-identical and the assertion `out == "13:00Z"` still holds).

- [ ] **Step 5: Coverage + type-check**

Run: `uv run pytest tests/unit/orchestrator/test_tool_dispatch.py --cov=src/alfred/orchestrator/tool_dispatch --cov-report=term-missing -v`
Expected: 100% line + branch on `tool_dispatch.py` (CLAUDE.md hard rule: trust-boundary code, no exceptions) — the new canary-trip arm must show as covered, not just the happy path.

Run: `uv run mypy src/alfred/orchestrator/tool_dispatch.py && uv run pyright src/alfred/orchestrator/tool_dispatch.py`
Expected: no errors.

- [ ] **Step 6: Add adversarial-corpus coverage for the InternalToolSpec DLP surface**

> **Added per `/review-plan` finding test-001 (High, corroborated — cross-check confirmed by `alfred-security-engineer`, which added a sequencing note: write this AFTER Step 3's totality-wrapper fix is settled, so it can assert both outcomes below in one pass, not just the canary case).**

Zero adversarial-corpus coverage exists today for the `InternalToolSpec` DLP-scan surface this task introduces/fixes (distinct from cap-2026-010's unknown-tool-name property, which Task 4 Step 6 already extends end-to-end). Add a new corpus entry under `tests/adversarial/` (follow this repo's existing corpus file/naming convention — check a sibling entry such as `test_cap_2026_010_011_dispatch_perimeter_injection.py` for the pattern) asserting BOTH outcomes through `dispatch_tool` on the `InternalToolSpec` leg:

- A canary-bearing tool result → `dispatch_outcome="dlp_canary"`, `result="quarantined"`, escalated (`OutboundCanaryTripped` propagates).
- A non-canary DLP fault (mirrors Step 1's `test_internal_tool_dlp_non_canary_fault_is_audited`) → `dispatch_outcome="unexpected_error"`, `result="fault"`, audited before propagating.

Run: `uv run pytest tests/adversarial -q` — the new entry plus every pre-existing adversarial test must pass.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/orchestrator/tool_dispatch.py tests/unit/orchestrator/test_tool_dispatch.py tests/adversarial/
git commit -m "fix(security): scan InternalToolSpec dispatch results through DLP, with totality-wrapper audit coverage (#410 PR3)"
```

---

### Task 3: Positive test for the dispatch-seams guard

**Files:**

- Modify: `tests/unit/orchestrator/test_act_loop.py` (`test_constructor_defaults_tool_seams_to_none` already covers the negative all-`None` case; this adds the positive all-wired case)

The existing `core.py` guard (currently ~`:1364`, verify against the live file — confirmed present and unchanged in shape post-PR1/PR2, at `if self._tool_registry is None or self._gate is None or self._outbound_dlp is None: raise ...`) has only ever been exercised with all three `None` (the pre-#410 state) or, via `test_act_loop.py`'s `TestActLoopOrderedDispatch`, all three wired via `_make_orchestrator(..., tool_registry=..., gate=..., outbound_dlp=...)` — but that test never asserts the GUARD ITSELF is bypassed correctly; it asserts dispatch behaviour. Add an explicit, minimal test naming the guard.

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding core-003, Low, cross-check confirmed by `alfred-test-engineer`):** the pre-existing `TestActLoopOrderedDispatch::test_two_tool_turn_dispatches_in_order_then_returns` ALREADY logically entails "the guard did not raise" — its outcome (a completed turn, `router.complete.await_count == 2`) is reachable only if the guard's single bare-raise branch didn't fire. The test below adds no coverage that test doesn't already provide, given the guard's trivial single-condition shape. Keep it, but as an honestly-framed **named regression-pin** (a readable, explicit anchor a future refactor can't silently break without a failure pointing at the right place) — not as new coverage.

- [ ] **Step 1: Write the test**

```python
async def test_dispatch_seams_guard_is_bypassed_when_all_three_wired(
    monkeypatch: Any,
) -> None:
    """Named regression-pin for core.py's all-three-or-none guard (~:1364):
    never fires when genuinely all three are set. Logically already entailed
    by test_two_tool_turn_dispatches_in_order_then_returns's passing outcome
    — this test exists to name the guard explicitly for readability, not to
    add new coverage."""
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

**Critical, found during `/review-plan` (2026-08-07), re-confirmed still true against `main` post-PR1/PR2 (2026-08-11):** `_boot_stack`'s gate fixture (`_boot_gate(*, grant_downgrade: bool)`, this same file, currently `:287-317`) still does not seed a `tool.dispatch` capability grant — it predates #410 and only ever needed the downgrade + DLP-subscriber grants. `dispatch_tool` (`src/alfred/orchestrator/tool_dispatch.py`) calls `gate.check(plugin_id="alfred.orchestrator.tool_dispatch", hookpoint="tool.dispatch", requested_tier="system")` before dispatching anything, and `GatePolicy.check()` fails CLOSED on any unmatched grant (`src/alfred/security/capability_gate/policy.py`). Without this grant, Task 4's flagship test would silently exercise the gate-**denied** branch, not the success path it claims to prove — and nothing in the test as drafted would catch that (the router double ignores tool-result content and returns its fixed answer regardless).

**Concrete mechanism (verified against `tests/integration/orchestrator/conftest.py`'s `_assembly_gate()`, `:107-141` — the established precedent for composing `make_tool_dispatch_gate()`'s grants onto a different base gate):** `make_tool_dispatch_gate()` (`tests/helpers/gates.py:637`) returns a full `RealGate`, not a bare grant set — `_assembly_gate()` extracts its grants via `base = make_tool_dispatch_gate(); assert isinstance(base, RealGate); grants = set(base._policy.grants)`, unions in whatever else it needs, then rebuilds ONE `RealGate` from the union. Apply the same pattern inside `_boot_gate()`: call `make_tool_dispatch_gate(grant_downgrade=False)` (pass `grant_downgrade=False` — `_boot_gate()` already conditionally seeds its OWN `t3.downgrade_to_orchestrator` grant via its own `grant_downgrade` param; do not let the two params fight each other over the same grant), pull the single `tool.dispatch` `GrantRow` out of its `._policy.grants`, and add it to `_boot_gate()`'s existing local `grants` set before constructing the returned `RealGate` — never a second gate object, and never a permissive shim (CLAUDE.md hard rule #2). This is additive: every existing test in this file that doesn't dispatch tools is unaffected by one more grant existing on the gate.

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

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding arch-001, Medium, cross-check confirmed by `alfred-reviewer`):** this grep returns MULTIPLE stale hits, not one — a "Neutral"-section "deferred journal" bullet goes stale too (PR3 activates the journal), separate from the Decision-section site Step 2 below targets. Add a superseding note at EVERY hit the grep surfaces, not just the first/most prominent one — re-run the grep after editing to confirm no stale hit was missed.

- [ ] **Step 2: Add a superseding note**

At each location Step 1 finds (fill in today's actual date at implementation time, not a placeholder), add:

```markdown
> **Superseded in part by #410 PR3.** The "egress tools deferred... empty
> tool registry" premise below no longer holds: the live comms turn now
> dispatches `clock.now` for real. `web.fetch` remains deferred — not for
> the reason below (tool-calling itself), but because its operator-allowlist
> projection is unfinished (see
> `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md` §3 item 6).
> The original text is preserved for historical record.
```

- [ ] **Step 3: Update the comms subsystem deep-doc's matching stale premise**

> **Added per `/review-plan` finding comms-002 (Medium, cross-check confirmed by `alfred-architect`, who weighted this AT LEAST as important as arch-001 given it's the operator-facing subsystem doc, not a historical ADR record — bundle into this same edit pass rather than deferring).**

`docs/subsystems/comms.md` (its "PRIVILEGED side now runs a real LLM turn" paragraph, live file ~lines 385-393) carries the same "egress tools deferred" premise this task supersedes in ADR-0049 — after this PR it becomes materially misleading (`clock.now` is live; only `web.fetch`/egress specifically stays deferred). Update it to note `clock.now` genuinely dispatches post-PR3, with `web.fetch` specifically still deferred pending #582/#583/#584.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0049-real-privileged-turn-comms-inbound.md docs/subsystems/comms.md
git commit -m "docs(adr): ADR-0049 — supersede the empty-tool-registry premise, and comms.md (#410 PR3)"
```

---

### Task 6: File the two forward-looking issues (now three — see correction)

**Files:** none (GitHub issues, not repo files)

> **Steps 1-2 are DONE — filed during PR0 bookkeeping, 2026-08-11, ahead of
> this plan's execution** (the bookkeeping session filed them early rather
> than waiting for PR3 to reach this task). Filed as:
>
> - **#582** — "web.fetch operator-allowlist projection is unwired
>   (`_list_allowlist_entries` always returns `[]`)"
> - **#583** — "Activate web.fetch on the live comms turn (unauthenticated) —
>   blocked on the allowlist projection (#582)"
>
> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 —
> finding arch-002, High, cross-check confirmed by
> `alfred-security-engineer`, who called the per-secret↔destination binding
> "exactly the confused-deputy control the secret broker exists to
> enforce"):** the design spec §9 promises a THIRD follow-up issue —
> authenticated `web.fetch` (the ADR-0048 forward gates: per-secret↔destination
> binding, the gateway re-scan positive-path residual) — that was never
> filed. Filed during this same review-fix pass as:
>
> - **#584** — "Authenticated web.fetch: per-secret↔destination binding +
>   gateway re-scan residual (ADR-0048 forward gates)"
>
> **Step 3** (cross-reference all three issue numbers into the design spec's
> §9) remains — do it as part of this PR. See its correction below re: `#583`
> and `#584` needing NEW text, not a placeholder substitution.

- [x] **Step 1: File the allowlist-projection gap — DONE, filed as #582 (2026-08-11)**

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

- [x] **Step 2: File the web.fetch activation follow-up (references the one-broker-instance fix already researched) — DONE, filed as #583 (2026-08-11)**

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

- [ ] **Step 3: Cross-reference all three new issues from the design spec**

> **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — findings rev-003/core-002, Low, both independently found the identical gap):** the design spec's §9 contains exactly ONE literal "file one" placeholder (currently at line 411, mapping to the allowlist-projection gap). There is no second placeholder site for the unauthenticated-activation follow-up, and — per this correction — no third for the authenticated follow-up either. Grep for `"file one"` and substitute `#582` at the single hit; for `#583` and `#584`, ADD new cross-referencing text near the relevant §9 bullets (the unauthenticated `web.fetch` bullet and the authenticated `web.fetch` bullet respectively) rather than trying to substitute a placeholder that doesn't exist for them.

Update `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md`'s §9 "Out of scope" bullets to cross-reference the actual issue numbers: **#582** (allowlist-projection gap, substitutes the one "file one" placeholder), **#583** (unauthenticated web.fetch activation, new text), and **#584** (authenticated web.fetch, ADR-0048 forward gates, new text).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md
git commit -m "docs(plan): cross-reference #582/#583/#584 into the design spec's out-of-scope section (#410 PR3)"
```

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
- No `orchestrator.turn` fault/error row correlated with the UAT's `tool.dispatch` row in the audit graph (a POSITIVE assertion, consistent with Task 4 Step 2's own preference for positive assertions over "not a known failure string" checks). **Correction (found during the `/review-plan` fleet pass, 2026-08-11 — finding comms-003, Medium, cross-check confirmed by `alfred-test-engineer`):** the original wording here checked `docker compose logs alfred-core --since 1h` for the literal substring `dispatch_seams_unwired` — that is the i18n catalog KEY, not the rendered message. The live `en` catalog renders it as "Tool dispatch is not fully wired: registry, gate, and DLP must be configured together." — the key substring never appears in production logs via the normal caught-and-logged path, so the original check was vacuous (it would "pass" whether or not the guard fired). Use the audit-graph assertion above instead; if a log check is still wanted, grep for the RENDERED string ("Tool dispatch is not fully wired"), not the key.

- [ ] **Step 4: Record the UAT result**

Per this repo's standing cadence, note the UAT pass/fail in the PR description before requesting `/review-pr` + CodeRabbit.

---

## Definition of Done

- [ ] All 7 tasks' tests pass: `uv run pytest tests/unit/cli/test_build_orchestrator_wiring.py tests/unit/orchestrator/test_act_loop.py tests/unit/orchestrator/test_tool_dispatch.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py tests/integration/cli/daemon/test_comms_boot_graph_real_turn.py tests/adversarial -v`
- [ ] `make check` passes clean.
- [ ] 100% line+branch coverage on `src/alfred/orchestrator/tool_dispatch.py` (dual-LLM boundary, release-blocking).
- [ ] `alfred-security-engineer` sign-off obtained (dual-LLM boundary, first live comms-path tool dispatch).
- [ ] Manual UAT (Task 7) recorded pass.
- [ ] `/review-plan` fleet run on this plan (and PR1's, PR2's) before implementation; full `/review-pr` fleet + CodeRabbit `full review` on the resulting PR before merge.
- [ ] All three forward-looking issues (#582/#583/#584, Task 6) filed and cross-referenced from the design spec.
- [ ] New adversarial-corpus entry (Task 2a Step 6) covers both the canary and non-canary `InternalToolSpec` DLP-fault outcomes.
