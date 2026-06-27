# G4b-1 — Link-state machine: breaker → UNAVAILABLE escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the pure `LinkStateMachine` (`src/alfred/gateway/link_state.py`) with a `BREAKER_TRIPPED` event and a terminal `UNAVAILABLE` state, so the G4 back-pressure breaker (spec §5) escalates the link to a loud, absorbing `link.unavailable` — shipped *unwired* (no caller emits it yet), exactly as `LinkControl.UNAVAILABLE` itself was shipped defined-but-unemitted in G3-3a.

**Architecture:** A pure additive change to the existing `(state, event) -> (next_state, LinkControl | None)` transition table. Adds one event (`BREAKER_TRIPPED`), one state (`UNAVAILABLE`), and nine transitions: the four live states each escalate to `UNAVAILABLE` emitting `LinkControl.UNAVAILABLE` once, and `UNAVAILABLE` absorbs every event thereafter emitting nothing (a wedged buffer is not un-wedged by a core coming back — only a `discard` + fresh session recovers, which is a fresh machine). No new dependency; `control_notification` already maps `LinkControl.UNAVAILABLE`. The §9 invariant is refined: a gap's control sequence is `[RECONNECTING, RESTORED]` (recovered), `[RECONNECTING, UNAVAILABLE]` or `[UNAVAILABLE]` (wedged, terminal), or `[RECONNECTING]` (open) — never `RESTORED` without a preceding `RECONNECTING`, and never any control after `UNAVAILABLE`.

**Tech Stack:** Python 3.12+ (`StrEnum`, `Final`, PEP 604), `mypy --strict` + `pyright`, `ruff`, `pytest` + `hypothesis`. No new deps. Pure module — no I/O, no clock.

---

## Context the engineer needs

**Where this sits.** Spec A **G4b-1** of the Comms-Resume Gateway (#237) — the first, bounded PR of the G4-wiring epic. G4a (the pure `ReplayBuffer`) merged. The buffer exposes `breaker_tripped` (a latch set on a soft-cap breach, cleared only by `discard`). G4b-2 (next PR) wires the relay to feed this machine `BREAKER_TRIPPED` when the buffer trips, halting the client read (back-pressure) and emitting `link.unavailable`. **This PR (G4b-1) only extends the pure machine; nothing feeds the new event yet** — the same defined-but-unwired precedent the codebase already set for `LinkControl.UNAVAILABLE` (`link_state.py:84-86`).

**Read before coding:** `src/alfred/gateway/link_state.py` (the whole file — the `GatewayLinkState` / `GatewayLinkEvent` / `LinkControl` enums, the `_TRANSITIONS` table, the `feed` method, the `GatewayLinkStateError` fail-loud), `src/alfred/gateway/_control_frames.py` (the exhaustive `control_notification` map — already handles `LinkControl.UNAVAILABLE` → `LinkUnavailableNotification`, so NO change is needed there; the `assert_never` proves exhaustiveness), and `tests/unit/gateway/test_link_state.py` (the existing example + hypothesis property tests you will extend).

**Today's machine (verified):**

- States (`link_state.py:45-59`): `UP`, `DOWN_SIGNALLED`, `DOWN_CRASH`, `REDIALING`. **No `UNAVAILABLE` state.**
- Events (`link_state.py:61-79`): `CORE_GOING_DOWN`, `CORE_CRASH_EOF`, `REDIAL_STARTED`, `CORE_READY`. **No `BREAKER_TRIPPED`** (the docstring at `:62-66` explicitly flags it as a G4 event not modelled yet).
- `LinkControl` (`link_state.py:81-91`): `RECONNECTING`, `RESTORED`, `UNAVAILABLE` — `UNAVAILABLE` exists but **no transition emits it today**.
- `_TRANSITIONS` (`link_state.py:98-172`): explicit dict; an undefined `(state, event)` is ABSENT so `feed` raises `GatewayLinkStateError` (`link_state.py:192-197`).

**The design decisions (bake these into the code + tests):**

1. **`BREAKER_TRIPPED` is valid from ALL four live states.** The buffer can trip while the link is `UP` — the spec §6(d) *wedged-but-connected core* (accepts the socket, stops acking) fills the buffer while the link never dropped. So `UP + BREAKER_TRIPPED → UNAVAILABLE` is a real, important edge (operator sees `unavailable` with NO preceding `reconnecting`, which is correct — nothing reconnected). The gap states (`DOWN_SIGNALLED`, `DOWN_CRASH`, `REDIALING`) also escalate (buffer filled while the core was down and never came back in time).
2. **First trip emits `LinkControl.UNAVAILABLE` exactly once.** The relay (G4b-2) checks `buffer.breaker_tripped` after every append and may feed `BREAKER_TRIPPED` repeatedly while latched; the machine must emit `UNAVAILABLE` only on the first escalation, then be idempotent.
3. **`UNAVAILABLE` is an ABSORBING state.** Every event from `UNAVAILABLE` → `(UNAVAILABLE, None)`. A core coming back `CORE_READY` does NOT un-wedge the buffer (the buffer's breaker latch clears only on `discard`); a bare `CORE_READY` must therefore NOT emit a spurious `RESTORED`. Modelling every event as absorbing-with-no-emit also means a buggy/racy G4b-2 wiring that feeds a lifecycle event after escalation never fail-loud-crashes the machine on a *legitimate* late event. Recovery is a fresh session = a fresh `LinkStateMachine(UP)` (G4b-2's call), not an in-place `UNAVAILABLE` exit.
4. **§9 invariant refinement.** The original invariant ("exactly one control per gap; no `restored` without `reconnecting`") is widened: the terminal `UNAVAILABLE` escalation is the second-and-final control a gap may emit, and once `UNAVAILABLE` is emitted no further control (esp. `RESTORED`) is possible. The hypothesis property must be updated to: over any random event sequence, (a) `RESTORED` is never emitted without an earlier `RECONNECTING` since the last `UP`, (b) no control is emitted after the first `UNAVAILABLE`, (c) `feed` never raises (the table is now total over the full `state × event` space once `UNAVAILABLE` absorbs — see Task 4).

**Totality note (important for the property test + coverage):** after this change, is `_TRANSITIONS` total over `state × event`? **CORRECTION (architect-adjudicated, 2026-06-15):** the original draft of this note over-claimed a 25-pair total table. The shipped kernel deliberately leaves ONE pair undefined — the H2-sanctioned hole `(UP, REDIAL_STARTED)` (a redial cannot begin while the link is up; `feed` fail-louds on it, pinned by `test_undefined_transition_fails_loud` and the `GatewayLinkStateError` docstring). The four original states already define all four original events (minus that one hole = 15 pairs). Adding `BREAKER_TRIPPED` adds 4 escalation rows + 5 absorbing rows = 9. So the table is **total over `state × event` EXCEPT the one H2-sanctioned hole `(UP, REDIAL_STARTED)`** — 24 pairs defined, 1 deliberately absent. `feed` therefore raises only on that hole (and any genuinely-future unmodelled pair). KEEP the `GatewayLinkStateError` guard and its test — the fail-loud backstop stays meaningful precisely because the hole stays absent. Do NOT add a `(UP, REDIAL_STARTED)` row to "complete" the table (that would delete a deliberate fail-loud edge — out of G4b-1 scope).

**i18n:** none — the operator-facing `unavailable` *string* is rendered from `LinkUnavailableNotification` downstream (the TUI banner), not here. This module has only developer-facing exception text. No `t()`.

---

## File structure

- **Modify:** `src/alfred/gateway/link_state.py` — add `GatewayLinkState.UNAVAILABLE`, `GatewayLinkEvent.BREAKER_TRIPPED`, nine `_TRANSITIONS` rows, refine the module/`feed` docstrings for the §9 invariant.
- **Modify:** `tests/unit/gateway/test_link_state.py` — add escalation example tests + absorbing-state tests + extend/refine the hypothesis property.
- **No change** to `_control_frames.py` (already maps `UNAVAILABLE`), `__init__.py` (enums already exported via the module), or `ci.yml` (`link_state.py` is already in both per-file 100% gates).

---

### Task 1: Add the `UNAVAILABLE` state and `BREAKER_TRIPPED` event

**Files:**

- Modify: `src/alfred/gateway/link_state.py`
- Test: `tests/unit/gateway/test_link_state.py`

- [ ] **Step 1: Write the failing test**

```python
def test_unavailable_state_and_breaker_event_exist() -> None:
    from alfred.gateway.link_state import GatewayLinkEvent, GatewayLinkState

    assert GatewayLinkState.UNAVAILABLE == "unavailable"
    assert GatewayLinkEvent.BREAKER_TRIPPED == "breaker_tripped"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k unavailable_state_and_breaker`
Expected: FAIL — `AttributeError: UNAVAILABLE` / `BREAKER_TRIPPED`.

- [ ] **Step 3: Write minimal implementation**

In `link_state.py`, add the state to `GatewayLinkState` (after `REDIALING`):

```python
    UNAVAILABLE = "unavailable"
    """The buffer's back-pressure breaker tripped (spec §5): a terminal, absorbing
    state. The gap is escalated to ``link.unavailable``; recovery is a fresh session
    (a new machine), never an in-place exit — the buffer's breaker latch clears only
    on ``discard``."""
```

And the event to `GatewayLinkEvent` (after `CORE_READY`, and delete the now-stale "NB: ``breaker_tripped``… is a G4 event… NOT modelled here" note in the enum docstring):

```python
    BREAKER_TRIPPED = "breaker_tripped"
    """The ReplayBuffer's back-pressure breaker tripped (soft-cap breach, spec §5).
    Fed by the G4b relay when ``buffer.breaker_tripped`` is observed after an append;
    escalates the link to the absorbing ``UNAVAILABLE`` state."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k unavailable_state_and_breaker`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/link_state.py tests/unit/gateway/test_link_state.py
git commit -m "feat(gateway): link-state UNAVAILABLE state + BREAKER_TRIPPED event (Spec A G4b-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: Escalation transitions — the four live states → UNAVAILABLE (emit once)

**Files:**

- Modify: `src/alfred/gateway/link_state.py`
- Test: `tests/unit/gateway/test_link_state.py`

- [ ] **Step 1: Write the failing test**

```python
import pytest

from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    LinkControl,
    LinkStateMachine,
)


@pytest.mark.parametrize(
    "to_gap",
    [
        [],  # UP -> breaker (wedged-but-connected core; no prior reconnecting)
        [GatewayLinkEvent.CORE_GOING_DOWN],  # DOWN_SIGNALLED -> breaker
        [GatewayLinkEvent.CORE_CRASH_EOF],  # DOWN_CRASH -> breaker
        [GatewayLinkEvent.CORE_GOING_DOWN, GatewayLinkEvent.REDIAL_STARTED],  # REDIALING -> breaker
    ],
)
def test_breaker_escalates_each_live_state_to_unavailable_once(
    to_gap: list[GatewayLinkEvent],
) -> None:
    m = LinkStateMachine()
    for ev in to_gap:
        m.feed(ev)
    assert m.feed(GatewayLinkEvent.BREAKER_TRIPPED) is LinkControl.UNAVAILABLE
    assert m.state is GatewayLinkState.UNAVAILABLE


def test_up_breaker_emits_unavailable_without_a_preceding_reconnecting() -> None:
    """The wedged-but-connected-core case: link never dropped, so no RECONNECTING first."""
    m = LinkStateMachine()
    assert m.feed(GatewayLinkEvent.BREAKER_TRIPPED) is LinkControl.UNAVAILABLE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k "escalates or without_a_preceding"`
Expected: FAIL — `GatewayLinkStateError: undefined link transition ... BREAKER_TRIPPED`.

- [ ] **Step 3: Write minimal implementation**

Add to `_TRANSITIONS` (a new `--- BREAKER (G4b-1) ---` section before the closing brace):

```python
    # --- BREAKER escalation (G4b-1, spec §5) ------------------------------
    # The buffer's back-pressure breaker trips -> escalate to the terminal
    # UNAVAILABLE, emitting link.unavailable exactly ONCE. Valid from every live
    # state: UP covers the wedged-but-connected core (spec §6(d) — the link never
    # dropped, so there is no preceding RECONNECTING); the gap states cover a buffer
    # that filled while the core was down and never returned in time.
    (GatewayLinkState.UP, GatewayLinkEvent.BREAKER_TRIPPED): (
        GatewayLinkState.UNAVAILABLE,
        LinkControl.UNAVAILABLE,
    ),
    (GatewayLinkState.DOWN_SIGNALLED, GatewayLinkEvent.BREAKER_TRIPPED): (
        GatewayLinkState.UNAVAILABLE,
        LinkControl.UNAVAILABLE,
    ),
    (GatewayLinkState.DOWN_CRASH, GatewayLinkEvent.BREAKER_TRIPPED): (
        GatewayLinkState.UNAVAILABLE,
        LinkControl.UNAVAILABLE,
    ),
    (GatewayLinkState.REDIALING, GatewayLinkEvent.BREAKER_TRIPPED): (
        GatewayLinkState.UNAVAILABLE,
        LinkControl.UNAVAILABLE,
    ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k "escalates or without_a_preceding"`
Expected: PASS (5 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/link_state.py tests/unit/gateway/test_link_state.py
git commit -m "feat(gateway): breaker escalates every live link state to UNAVAILABLE once (Spec A G4b-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 3: UNAVAILABLE is absorbing — every event stays, emits nothing

**Files:**

- Modify: `src/alfred/gateway/link_state.py`
- Test: `tests/unit/gateway/test_link_state.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.parametrize(
    "event",
    [
        GatewayLinkEvent.BREAKER_TRIPPED,  # repeated trip while latched -> idempotent
        GatewayLinkEvent.CORE_READY,  # core revived but buffer still wedged -> NO restored
        GatewayLinkEvent.CORE_GOING_DOWN,
        GatewayLinkEvent.CORE_CRASH_EOF,
        GatewayLinkEvent.REDIAL_STARTED,
    ],
)
def test_unavailable_absorbs_every_event_emitting_nothing(event: GatewayLinkEvent) -> None:
    m = LinkStateMachine()
    m.feed(GatewayLinkEvent.BREAKER_TRIPPED)  # -> UNAVAILABLE
    assert m.feed(event) is None
    assert m.state is GatewayLinkState.UNAVAILABLE


def test_core_ready_after_unavailable_never_emits_restored() -> None:
    """A wedged buffer is not un-wedged by a core returning — recovery is a fresh session."""
    m = LinkStateMachine()
    m.feed(GatewayLinkEvent.CORE_GOING_DOWN)  # -> DOWN_SIGNALLED, RECONNECTING
    m.feed(GatewayLinkEvent.BREAKER_TRIPPED)  # -> UNAVAILABLE, UNAVAILABLE
    assert m.feed(GatewayLinkEvent.CORE_READY) is None  # NOT RESTORED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k "absorbs or after_unavailable"`
Expected: FAIL — `GatewayLinkStateError: undefined link transition state='unavailable' ...`.

- [ ] **Step 3: Write minimal implementation**

Add the absorbing rows to `_TRANSITIONS` (under the BREAKER section):

```python
    # --- UNAVAILABLE (absorbing) ------------------------------------------
    # Terminal: every event keeps the machine here and emits nothing. A repeated
    # BREAKER_TRIPPED (the relay re-feeds while the latch holds) is idempotent — the
    # gap was already escalated. A CORE_READY does NOT un-wedge the buffer (its
    # breaker latch clears only on ``discard``), so it must never emit a spurious
    # RESTORED. Recovery is a fresh session (a new machine), not an in-place exit.
    (GatewayLinkState.UNAVAILABLE, GatewayLinkEvent.BREAKER_TRIPPED): (
        GatewayLinkState.UNAVAILABLE,
        None,
    ),
    (GatewayLinkState.UNAVAILABLE, GatewayLinkEvent.CORE_READY): (
        GatewayLinkState.UNAVAILABLE,
        None,
    ),
    (GatewayLinkState.UNAVAILABLE, GatewayLinkEvent.CORE_GOING_DOWN): (
        GatewayLinkState.UNAVAILABLE,
        None,
    ),
    (GatewayLinkState.UNAVAILABLE, GatewayLinkEvent.CORE_CRASH_EOF): (
        GatewayLinkState.UNAVAILABLE,
        None,
    ),
    (GatewayLinkState.UNAVAILABLE, GatewayLinkEvent.REDIAL_STARTED): (
        GatewayLinkState.UNAVAILABLE,
        None,
    ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k "absorbs or after_unavailable"`
Expected: PASS (6 cases).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/link_state.py tests/unit/gateway/test_link_state.py
git commit -m "feat(gateway): UNAVAILABLE is an absorbing sink — no spurious restored after breaker (Spec A G4b-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 4: Refine the §9 hypothesis invariant for the breaker escalation

**Files:**

- Modify: `src/alfred/gateway/link_state.py` (docstring only — refine the §9 invariant prose in the module docstring + `feed`)
- Test: `tests/unit/gateway/test_link_state.py` (extend the existing property test, or add a new one, over the FULL event set including `BREAKER_TRIPPED`)

- [ ] **Step 1: Read the existing property test — and DO NOT widen its event set**

Open `tests/unit/gateway/test_link_state.py` and find the existing happy-path property `test_restored_always_preceded_by_reconnecting` (~lines 175-211). It feeds random events from an explicit four-event tuple `_ALL_EVENTS` (~line 167) and, crucially, ends with a load-bearing cross-check at ~line 211: `assert gap_open == (machine.state is not GatewayLinkState.UP)`.

**That cross-check is FALSE once the breaker exists** — `UNAVAILABLE` is not-`UP` yet is NOT a gap-open state (e.g. `UP + BREAKER_TRIPPED → UNAVAILABLE` with no outstanding `RECONNECTING`). So: **LEAVE `_ALL_EVENTS` as the four pre-breaker events** (do NOT widen it to include `BREAKER_TRIPPED`, and do NOT switch it to `list(GatewayLinkEvent)`). Add a one-line comment on `_ALL_EVENTS` saying the breaker is covered by the new property below. Keeping it unchanged means this test never reaches `UNAVAILABLE`, so its line-211 invariant stays valid and the test passes untouched. The breaker coverage lives entirely in the new property in Step 2.

- [ ] **Step 2: Write the failing/extended test**

Add a property that exercises the breaker escalation and the absorbing terminal across random sequences. Use the full event set so `BREAKER_TRIPPED` is generated:

```python
from hypothesis import given
from hypothesis import strategies as st


@given(st.lists(st.sampled_from(list(GatewayLinkEvent)), min_size=0, max_size=40))
def test_invariant_no_control_after_unavailable_and_no_unprefixed_restored(
    events: list[GatewayLinkEvent],
) -> None:
    """§9 (refined for G4b-1): RESTORED only after a RECONNECTING since the last UP;
    no control of ANY kind once UNAVAILABLE has been emitted; feed never raises."""
    m = LinkStateMachine()
    reconnecting_open = False
    unavailable_emitted = False
    for ev in events:
        # CORRECTION (architect-adjudicated): feed raises only on the H2 hole
        # (UP, REDIAL_STARTED) — skip it exactly as the existing §9 property does.
        if m.state is GatewayLinkState.UP and ev is GatewayLinkEvent.REDIAL_STARTED:
            with pytest.raises(GatewayLinkStateError):
                m.feed(ev)
            continue
        control = m.feed(ev)  # raises only on the H2 hole, skipped above
        if unavailable_emitted:
            assert control is None  # absorbing terminal: nothing after UNAVAILABLE
        if control is LinkControl.RECONNECTING:
            reconnecting_open = True
        elif control is LinkControl.RESTORED:
            assert reconnecting_open, "RESTORED without a preceding RECONNECTING"
            reconnecting_open = False
        elif control is LinkControl.UNAVAILABLE:
            unavailable_emitted = True
        # State cross-check (the line-211 analogue for the terminal sink): once
        # UNAVAILABLE has been emitted the machine state is forever the terminal
        # sink. This catches a "right control frame, wrong next_state" table typo
        # the control-only bookkeeping above would otherwise miss.
        if unavailable_emitted:
            assert m.state is GatewayLinkState.UNAVAILABLE
```

- [ ] **Step 2b: Add a totality test** (the table is total over `state × event` EXCEPT the one H2-sanctioned hole)

**CORRECTION (architect-adjudicated, 2026-06-15):** the draft below asserted a flat 25-pair totality, which conflicts with the shipped H2 hole `(UP, REDIAL_STARTED)`. The reconciled test pins totality EXCEPT that one hole (24 present + the hole explicitly absent), so the fail-loud guard + its test stay meaningful:

```python
import itertools

from alfred.gateway.link_state import _TRANSITIONS

# The one deliberately-undefined pair (H2 fix): a redial cannot begin while the
# link is UP — no gap is open, so feed(UP, REDIAL_STARTED) must fail loud.
_SANCTIONED_UNDEFINED: frozenset[tuple[GatewayLinkState, GatewayLinkEvent]] = frozenset(
    {(GatewayLinkState.UP, GatewayLinkEvent.REDIAL_STARTED)}
)


def test_transition_table_is_total_except_the_sanctioned_hole() -> None:
    """Every (state, event) has a row except the one fail-loud H2 hole.

    Pins both directions: (a) all 24 modelled pairs present, so a future hand-edit
    that drops a row fails here; (b) (UP, REDIAL_STARTED) stays ABSENT, so the
    fail-loud guard + its test remain meaningful. Complements (does not replace)
    test_undefined_transition_fails_loud.
    """
    for state, event in itertools.product(GatewayLinkState, GatewayLinkEvent):
        present = (state, event) in _TRANSITIONS
        if (state, event) in _SANCTIONED_UNDEFINED:
            assert not present, f"sanctioned hole must stay absent: {state} x {event}"
        else:
            assert present, f"missing transition: {state} x {event}"
```

- [ ] **Step 3: Run the new tests**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v -k "invariant_no_control_after_unavailable or table_is_total"`
Expected: PASS. A hypothesis counterexample = a REAL invariant break (fix the table, not the property). If `feed` raises or `test_transition_table_is_total` reports a missing pair, the table is not total — add the missing `(state, event)` row.

- [ ] **Step 4: Refine the docstrings**

Update the module docstring's "Spec §9 invariant" paragraph and `feed`'s docstring in `link_state.py` to state the refined invariant: a gap emits `[RECONNECTING(, RESTORED)]` on the happy path, or escalates to a terminal `UNAVAILABLE` (which may follow a `RECONNECTING`, or stand alone from `UP` on a wedged-but-connected core); once `UNAVAILABLE` is emitted the state absorbs and no further control is emitted. Keep the "undefined `(state, event)` → `GatewayLinkStateError`" note (the guard remains the fail-loud backstop even though the table is now total).

- [ ] **Step 5: Confirm the existing pre-G4b-1 property still holds**

Run: `uv run pytest tests/unit/gateway/test_link_state.py -v`
Expected: ALL pass — including the original happy-path property (it must still hold over sequences that never feed `BREAKER_TRIPPED`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/gateway/link_state.py tests/unit/gateway/test_link_state.py
git commit -m "test(gateway): §9 invariant extended for breaker escalation + absorbing terminal (Spec A G4b-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 5: Coverage + quality gates

**Files:**

- Verify only (no new edits unless coverage gaps).

- [ ] **Step 1: Confirm 100% line+branch on `link_state.py`**

Run: `uv run coverage run -m pytest tests/unit/gateway/test_link_state.py -q && uv run coverage report --include='src/alfred/gateway/link_state.py' --show-missing`
Expected: `link_state.py` at `100%`. Every new transition row is exercised (Tasks 2-3 cover all nine; the property test covers `feed` over the full space). If a row is uncovered, add a targeted example test.

- [ ] **Step 2: Full quality gates**

Run: `make check`
Expected: ruff format + ruff check clean, `mypy --strict` clean, pyright clean, unit + integration green. (Do NOT pipe through `tail`.)

- [ ] **Step 3: Confirm `_control_frames.py` still exhaustive (no new mapping needed)**

Run: `uv run pytest tests/unit/gateway/ -q -k control` (and the exhaustiveness test if present)
Expected: PASS — `control_notification` already maps `LinkControl.UNAVAILABLE`; G4b-1 adds no new `LinkControl` member, so the `assert_never` exhaustiveness holds with no change.

- [ ] **Step 3b: Prove the new event is shipped UNWIRED (no production emitter)**

Run: `grep -rn "BREAKER_TRIPPED" src/alfred --include='*.py'`
Expected: matches ONLY in `src/alfred/gateway/link_state.py` (the enum member + its transition rows). No production caller feeds it yet — the defined-but-unwired invariant, mirroring how `LinkControl.UNAVAILABLE` shipped unemitted in G3-3a. (Tests referencing it live under `tests/`, not `src/`, so they don't appear here.)

- [ ] **Step 4: Commit (only if Step 1 added a coverage test)**

```bash
git add tests/unit/gateway/test_link_state.py
git commit -m "test(gateway): cover remaining link-state breaker transition (Spec A G4b-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Task |
| --- | --- |
| `BREAKER_TRIPPED` event + `UNAVAILABLE` state | Task 1 |
| breaker escalates every live state → `UNAVAILABLE`, emit once | Task 2 |
| `UP`→`UNAVAILABLE` (wedged-but-connected core, no prior RECONNECTING) | Task 2 |
| idempotent re-trip + no spurious `RESTORED` (absorbing) | Task 3 |
| §9 invariant refined + hypothesis-pinned over the full event set | Task 4 |
| pure, no I/O, fail-loud guard retained, 100% coverage gate | Tasks 4, 5 |
| shipped unwired (no emitter) — mirrors the `UNAVAILABLE`-control precedent | whole PR |

**Scope discipline:** This PR ONLY extends the pure machine. It does NOT wire the relay/core_link to feed `BREAKER_TRIPPED` (that is G4b-2), does NOT touch the buffer, audit, or metrics. The new event is defined-but-unfed, exactly as `LinkControl.UNAVAILABLE` was defined-but-unemitted in G3-3a.

**Design decisions to flag for plan-review:** (a) `UP + BREAKER_TRIPPED → UNAVAILABLE` directly (the wedged-connected-core case — confirm this is the intended escalation, not a require-gap-first); (b) `UNAVAILABLE` is fully absorbing with recovery-via-fresh-session rather than an in-place `CORE_READY` exit (confirm this matches the intended G4b-2 recovery model — the alternative, a `discard`-then-`CORE_READY` recovery transition, is deliberately deferred to G4b-2 where the buffer/discard is actually wired); (c) the §9 invariant widening (two controls per gap on the wedged path).

**Placeholder scan:** none. **Type consistency:** `GatewayLinkState.UNAVAILABLE`, `GatewayLinkEvent.BREAKER_TRIPPED`, `LinkControl.UNAVAILABLE` used identically across tasks.

**G4b-2 follow-up (carry forward):** feed `BREAKER_TRIPPED` from the relay when `buffer.breaker_tripped`; halt the client read (back-pressure); `buffer.append` in the pump; trim-on-ack; reconnect-replay (`trim_to_ack(high_water)` then `unacked_frames()`, epoch-gated); audit every escalation/eviction/replay; the missing Prometheus gauges; the wedged-core-flood adversarial test.
