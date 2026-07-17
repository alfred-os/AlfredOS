# #443 PR1 — supervisor hookpoint declaration into the boot seam

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the supervisor a boot-declarable hookpoint publisher, so
`supervisor.plugin.sandbox_refused` is declared before `Supervisor(...)` exists —
the prerequisite for #443 PR2's in-spawn handshake, and the fix #444 is blocked on.

**Architecture:** Move `Supervisor._register_hookpoints`'s tuple into a
`declare_hookpoints(registry)` publisher at `src/alfred/supervisor/hookpoints.py`,
register it in the existing `hooks/boot.py:_declare_all_subsystem_hookpoints`
seam, and have `_register_hookpoints` delegate to it. One definition, two callers.

**Tech Stack:** Python 3.14+, pytest, `alfred.hooks` registry.

> **Rev 2 (2026-07-17).** Rewritten after a 5-reviewer plan review found the rev-1
> premise **false** and the plan **un-runnable**. See "What rev 1 got wrong".

## Global Constraints

- **No module-bottom `declare_hookpoints()` call** for the supervisor. core-010
  (`supervisor/core.py:1023-1028`) rejected import-time registration: pytest
  collects every test module's imports before any fixture runs, so publisher
  metadata would persist across tests expecting a clean registry. Add the
  *function*; never the import-time *call*. **Note the asymmetry honestly:** all
  nine existing publishers DO have a module-bottom call, so the supervisor becomes
  the only one without, guarded by nothing but a docstring. core-010's rationale
  applies equally to those nine — the asymmetry is inherited, not introduced here.
- **The tuple MUST stay function-local**, inline immediately before the `for` loop
  — see Task 1 Step 3. A module-level constant silently blinds a live drift guard.
- **`HookRegistry` cannot be constructed bare.** `gate` is keyword-only with no
  default (`hooks/registry.py:515-522`). Use `make_deny_all_gate()`
  (`tests/helpers/gates.py:186`) — declaration is not gated, only subscription is.
  **Never** stub the capability layer to "always allow" (CLAUDE.md hard rule #2);
  use a fixture gate.
- **`register_hookpoint` is idempotent on equal metadata, strict on drift**
  (`hooks/registry.py:587`). Drift compares **by value** — `registry.py:734` does
  `stored != new_meta` on a dataclass over eagerly-normalized frozensets, so
  `core.py:1035-1038`'s "SAME frozenset objects" is stricter than the code demands.
- **PR1 touches no file under `src/alfred/security/`**, so the adversarial suite is
  not *mandated* by CLAUDE.md here. Run it anyway (`uv run pytest tests/adversarial`):
  it exercises the `sandbox_refused` row family whose declaration timing this PR
  changes. Prudence, not a hard rule — say so accurately in the PR body.
- **`make check` before every push.** `make ... | tail` masks the exit code.
- **Commit subjects need a literal `#443` AFTER the colon** (`Conventional commit
  format` is a required check).
- **i18n:** no operator-facing strings here. structlog event keys are not `t()` scope.

## Why this PR exists — stated accurately

**core-001 is LATENT, not live.** Rev 1 claimed it was "a live hard-rule-#7 silent
fail-open on main today." **That is false**, and ADR-0051:81-89 says so verbatim:

> "(B) means core-001 … **is moot for this specific call site** — the dispatch
> happens well after `Supervisor.__init__` has already called
> `_register_hookpoints()`, so the hookpoint is always declared by then. A future
> boot-time fail-closed health-check (option A, deferred) would need to
> **re-examine core-001 for itself**, since a probe that runs before `Supervisor`
> is constructed cannot assume the hookpoint is declared yet."

Verified: `SandboxRefusalAuditor.record()` reaches `invoke` only via
`_record_launcher_refusals` (`quarantine_child_io.py:647`) ← the gate at `:580` ←
**only** `read_frame`'s except arm (`:488`) — `aclose` (`:674`) passes
`refusal_candidate=False` and can never reach it. And `_SubprocessChildIO.read_frame`
has exactly one driver: `quarantine_transport.py:307`, inside `dispatch()`, the
extract RPC — **turn time, after `Supervisor(...)` at `_commands.py:783`**.
`spawn_quarantine_child_io` contains zero `read_frame` calls.

So the hookpoint is always declared by the time anything dispatches it.

**What is true, and why this PR is still right work:**

1. The boot seam genuinely does **not** declare `supervisor.plugin.sandbox_refused`
   today — empirically confirmed: the seam registers 27 hookpoints and
   `hookpoint_meta("supervisor.plugin.sandbox_refused")` returns `None`.
2. **#443 PR2 makes that fatal.** PR2 moves the first read *into the spawn*
   (`_commands.py:658`), 125 lines before `Supervisor(...)`. Then the dispatch hits
   `strict_declarations` (`hooks/registry.py:521`) → `HookError`
   (`hooks/invoke.py:1439`) → caught by `_record_launcher_refusals` (`:648-652`) →
   demoted to a `refusal_record_failed` log line. The fail-closed T0 hookpoint
   would never fire, silently.
3. **#444 is blocked on exactly this fix.** Its body names it: *"its dispatch would
   be pre-`Supervisor` (needs the `declare_hookpoints()` fix — the
   `comms_mcp/hookpoints.py` convention)"*, echoed in ADR-0051's Follow-ups.

**PR1 is a prerequisite, not a bug fix.** Do not write "closes a live fail-open"
into the PR body, a docstring, or a corpus provenance field — that is the #434-436
failure mode, in the PR whose subject is declaration drift.

## What rev 1 got wrong (kept as the record)

A 5-reviewer plan review found **eight** false or unrunnable claims. All corroborated
3-5× and independently re-verified:

| rev-1 claim | reality |
| --- | --- |
| "core-001 is live on main today" | latent; ADR-0051:81-89 says it is moot for this call site |
| "rows 2..N are silently dropped" | only if `invoke` raises — it does not when declared |
| `HookRegistry()` in 4 tests | `TypeError`; `gate` is keyword-only, no default |
| module-level `SUPERVISOR_HOOKPOINTS` | silently blinds the drift guard: 10 names → **0**, still green |
| `git stash` proves the oracle bites | stashes the oracle, not the fix; 0 tests collected; exit 5 |
| "touches `src/alfred/security/`" | it touches no file there |
| "the coverage test kills zero mutants" | it kills the *ignores-the-`registry`-arg* mutant Task 1 depends on |
| "a count-assertion will need updating" | phantom — only a `>= 32` floor exists, unaffected |
| "two tuples reinstate drift" | overstated; disjoint sets cannot drift in the #432 sense |
| import block "from the module header" | they are function-local at `core.py:1063-1064` |

**The deviation (four tuples vs ten) was upheld — but rev 1's rationale was wrong.**
The real argument: spec §10 demands *both* "extract the four" *and* "drop the
`_StubSupervisor` dance", which are **incompatible**. Under 4/6 the six
breaker/lifecycle tuples stay reachable only via
`Supervisor._register_hookpoints(stub)`, so the dance must survive and
`_known_hookpoints.py` needs two supervisor keys. **Ten is the only scope that
delivers §10's own deliverables.** Security verified the widened window is safe:
`register()` gates strict-declaration (`:854`) → tier-allowlist (`:874`) →
capability gate (`:899`), and `SYSTEM_ONLY_TIERS` is `frozenset({'system'})`
(`:342`), so it admits only in-tree T0 code.

## File Structure

- **Create** `src/alfred/supervisor/hookpoints.py` — `declare_hookpoints(registry=None)`
  with the tuple **inline, function-local**.
- **Modify** `src/alfred/supervisor/core.py:1018-1132` — delegate; fix the "six"
  docstring (there are ten).
- **Modify** `src/alfred/hooks/boot.py:81-105` — one aliased import + one call.
- **Modify** `src/alfred/hooks/_known_hookpoints.py` — re-key the group (`:76`) and
  correct the now-false comment (`:47-55`).
- **Modify** three test files that carry the retired `_StubSupervisor` dance and/or
  stale docstrings.
- **Create** `tests/unit/supervisor/test_hookpoints_publisher.py`.

**Not in PR1:** `sbx-2026-021`. Its threat has no production path until PR2 moves
the read into the spawn, so its oracle would have to manufacture its own premise —
the self-referential oracle this repo has twice written down as worthless. The
adversarial corpus pins **reachable** threats; every entry 001-020 names one. It
ships with PR2, renumbered.

---

### Task 1: Publisher + boot wiring + delegation — ONE atomic commit

**Files:**

- Create: `src/alfred/supervisor/hookpoints.py`
- Modify: `src/alfred/supervisor/core.py:1018-1132`
- Modify: `src/alfred/hooks/boot.py:81-105`
- Test: `tests/unit/supervisor/test_hookpoints_publisher.py`

**Interfaces:**

- Consumes: `alfred.hooks.registry.HookRegistry` / `get_registry`;
  `SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS`, `T0`, `TrustTier` — the imports are
  **function-local at `core.py:1063-1064`**, not in the module header. Read that
  block; the module-level tuple is gone, so hoist only what the new module needs.
- Produces: `declare_hookpoints(registry: HookRegistry | None = None) -> None`.

**Why one commit:** `tests/unit/hooks/test_boot_registry.py:152-210` AST-walks every
`.py` under `src/alfred` for `def declare_hookpoints` and asserts each is both
imported into the aggregator with an **asname** (`:192`) and called with a
**positional arg named `registry`** (`:194-200`). So the instant the publisher file
lands, that guard fails until boot.py is wired. Splitting these would ship two red
commits and poison bisect. They are one deliverable.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/supervisor/test_hookpoints_publisher.py
"""The supervisor is a boot-declarable hookpoint publisher (#443 PR1).

Prerequisite for PR2's in-spawn handshake, which dispatches
``supervisor.plugin.sandbox_refused`` before ``Supervisor(...)`` exists. Also the
fix #444 is blocked on. core-001 is LATENT today — see the plan's rationale.
"""

from __future__ import annotations

from alfred.hooks.boot import _declare_all_subsystem_hookpoints
from alfred.hooks.registry import HookRegistry
from alfred.supervisor.hookpoints import declare_hookpoints
from tests.helpers.gates import make_deny_all_gate


def _registry() -> HookRegistry:
    """A real registry over a deny-all fixture gate.

    ``gate`` is keyword-only with no default (registry.py:515-522). Declaration is
    not gated — only subscription is — so deny-all is correct here and honours
    CLAUDE.md hard rule #2 (never stub the gate to "always allow").
    """
    return HookRegistry(gate=make_deny_all_gate())


def test_sandbox_refused_is_declared_fail_closed_t0() -> None:
    """PR2's target: the fail-closed T0 row, declarable without a Supervisor.

    Named independently of the tuple — an oracle that iterates the tuple and asks
    the tuple what the tuple says kills zero mutants.
    """
    registry = _registry()

    declare_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None
    assert meta.fail_closed is True


def test_declare_hookpoints_honours_the_registry_argument() -> None:
    """The passed registry is used, not the global singleton.

    Kills the "ignores the ``registry`` arg and calls get_registry()" mutant —
    which is exactly what the boot seam depends on.
    """
    registry = _registry()

    declare_hookpoints(registry)

    assert registry.hookpoint_meta("supervisor.breaker.tripped") is not None


def test_declare_hookpoints_is_idempotent() -> None:
    """Re-declaration on equal metadata is a no-op, not a drift raise.

    Load-bearing: the boot seam declares, then Supervisor.__init__ re-declares.
    """
    registry = _registry()

    declare_hookpoints(registry)
    declare_hookpoints(registry)  # must not raise


def test_boot_seam_declares_sandbox_refused_without_a_supervisor() -> None:
    """The core-001 oracle: the boot registry carries the row with no Supervisor.

    Fails before this task: the seam registers 27 hookpoints and this one is not
    among them.
    """
    registry = _registry()

    _declare_all_subsystem_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None, "core-001: sandbox_refused undeclared at boot"
    assert meta.fail_closed is True
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/supervisor/test_hookpoints_publisher.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.supervisor.hookpoints'`

- [ ] **Step 3: Write the publisher — tuple INLINE, function-local**

Read `src/alfred/supervisor/core.py:1018-1132` in full. Move the tuple and every
comment **verbatim** — cut and paste, do not retype: a transcription typo would
silently change a trust tier.

**The tuple MUST stay inline inside the function, immediately before the `for`
loop.** A module-level `SUPERVISOR_HOOKPOINTS` constant would silently blind a live
guard: `test_known_hookpoints_sync.py`'s AST resolver handles the function-local
`hookpoints = (...)`-then-`for` shape only (its docstring at `:345-347` names that
pattern), and falls through to `# Unresolvable — silently skip` at `:290`. A
reviewer ran the resolver both ways: **10 names today → 0 under a module-level
constant, still green.** That is the #432 silent-under-count residual, and this PR
must not reintroduce it.

```python
# src/alfred/supervisor/hookpoints.py
"""Boot-declarable hookpoint publisher for the supervisor (#443 PR1).

Extracted from ``Supervisor._register_hookpoints`` so the supervisor satisfies
``alfred.hooks.boot._declare_all_subsystem_hookpoints``'s stated obligation
(``boot.py:76-79``): every in-tree publisher MUST register there so its hookpoints
are declarable at boot. The supervisor was absent because its declaration was a
METHOD ON A CLASS, reachable only by constructing a ``Supervisor`` — making
``supervisor.plugin.sandbox_refused`` the only ``fail_closed=True`` security
hookpoint in the tree that a boot-time caller cannot declare.

That is harmless today (core-001 is moot for the current call site — ADR-0051:81-89;
the dispatch happens at first extraction, post-``Supervisor``). It becomes fatal at
#443 PR2, whose in-spawn handshake dispatches 125 lines BEFORE ``Supervisor(...)``:
under ``strict_declarations`` that raises ``HookError``, which the caller demotes to
a log line, so the fail-closed T0 hookpoint would never fire. #444 is blocked on the
same fix.

**No module-bottom ``declare_hookpoints()`` call — deliberately.** core-010
(``supervisor/core.py:1023-1028``) rejected import-time registration for these
hookpoints: pytest collects every test module's imports before any fixture runs, so
the metadata would persist across tests expecting a clean registry. The boot seam
calls this explicitly instead. Do not "fix" the omission — all nine other publishers
have a module-bottom call and the supervisor deliberately does not.

**The tuple is function-local on purpose.** ``test_known_hookpoints_sync.py``'s AST
drift resolver only resolves the inline ``hookpoints = (...)``-then-``for`` shape;
hoisting it to a module constant makes the resolver silently skip this module and
supervisor drift coverage drops to zero while staying green.

``Supervisor._register_hookpoints`` delegates here — one definition, two callers.
"""

from __future__ import annotations

# NOTE: copy the import spellings from supervisor/core.py:1063-1064 (they are
# FUNCTION-LOCAL there, not in the module header) plus HookRegistry/get_registry.


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register every supervisor hookpoint.

    Idempotent on equal metadata, strict on drift, so the boot seam and
    ``Supervisor.__init__`` may both call it.

    Args:
        registry: Optional override; defaults to the active singleton.
    """
    target = get_registry() if registry is None else registry
    # Per-hookpoint trust-tier rationale: <-- move core.py's comment block here.
    hookpoints: tuple[
        tuple[str, frozenset[str], frozenset[str], bool, type[TrustTier]], ...
    ] = (
        # <-- the TEN entries, verbatim from core.py:1075-1123, comments included.
    )
    for name, subscribable_tiers, refusable_tiers, fail_closed, carrier_tier in hookpoints:
        target.register_hookpoint(
            name=name,
            subscribable_tiers=subscribable_tiers,
            refusable_tiers=refusable_tiers,
            fail_closed=fail_closed,
            carrier_tier=carrier_tier,
        )
```

- [ ] **Step 4: Delegate `_register_hookpoints`**

Replace the body (`core.py:1018-1132`). Move the per-hookpoint rationale comments
into the publisher (Step 3) rather than deleting them. Fix the stale count: `:1021`
says "the supervisor's **six** hookpoints"; there are **ten**.

```python
    def _register_hookpoints(self) -> None:
        """Register every supervisor hookpoint with the global registry.

        Delegates to :func:`alfred.supervisor.hookpoints.declare_hookpoints` — the
        single definition, also called by the boot seam so the hookpoints are
        declarable before any ``Supervisor`` exists (#443 PR1).

        Kept as a method because tests and non-boot callers construct
        ``Supervisor`` directly and must still find the hookpoints declared;
        ``register_hookpoint`` is idempotent on equal metadata, so the double
        declaration is a no-op.

        core-010 still holds: the publisher exposes a FUNCTION, not an import-time
        side effect.
        """
        from alfred.supervisor.hookpoints import declare_hookpoints

        declare_hookpoints()
```

- [ ] **Step 5: Wire the boot seam**

In `hooks/boot.py:_declare_all_subsystem_hookpoints`, add to the function-local
import block (alphabetical) and the call list:

```python
    from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor
```

```python
    declare_supervisor(registry)
```

The **asname** and the **positional `registry`** are both required by the
completeness guard (`test_boot_registry.py:192`, `:194-200`) — not stylistic.

Keep the import function-local. The rationale is **import weight, not a cycle**:
`src/alfred/supervisor/` has zero module-level `alfred.hooks` imports, so no cycle
exists in either direction. But `supervisor/__init__.py:35` eagerly imports
`core.py` (dragging in sqlalchemy, structlog, audit_row_schemas, breaker…), and
Python always runs the parent package `__init__` first — so a module-level import
would make `alfred.hooks.boot` heavy, contradicting its own docstring
(`boot.py:63`: "Imports are local to keep `alfred.hooks.boot` import-light").

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/unit/supervisor/test_hookpoints_publisher.py -v`
Expected: 4 passed.

Run: `uv run pytest tests/unit/hooks tests/unit/supervisor tests/unit/cli/daemon -q`
Expected: all pass — **including** `test_boot_registry.py` (8 tests), which is the
completeness guard this task must satisfy, and `test_known_hookpoints_sync.py`.

- [ ] **Step 7: Prove the drift guard is still sighted (non-vacuity)**

The single highest-risk regression in this PR is silently blinding the resolver.
Prove it did not happen:

```bash
uv run pytest tests/unit/hooks/test_known_hookpoints_sync.py -q
```

Then **break the guarded code**: add a bogus entry `("supervisor.bogus.drift",
SYSTEM_ONLY_TIERS, frozenset(), False, T0),` to the publisher's tuple and re-run.
Expected: **FAIL** (the sync test sees an off-manifest registration).
Remove it; re-run. Expected: PASS.

**If it stays green with the bogus entry present, the resolver has gone blind** —
the tuple is not in the shape it can resolve. Stop and fix the shape; do not
proceed.

A guard's non-vacuity must be proven by breaking the guarded code, never asserted
(`domain_guard_completeness_and_oracle_independence`).

- [ ] **Step 8: Commit**

```bash
git add src/alfred/supervisor/hookpoints.py src/alfred/supervisor/core.py \
        src/alfred/hooks/boot.py tests/unit/supervisor/test_hookpoints_publisher.py
git commit -m "feat(supervisor): #443 make the supervisor a boot-declarable hookpoint publisher"
```

---

### Task 2: Re-key the drift map; retire all three stub sites; kill the stale docstrings

**Files:**

- Modify: `src/alfred/hooks/_known_hookpoints.py` (`:47-55` comment, `:76` key)
- Modify: `tests/unit/hooks/test_known_hookpoints_sync.py` (`:23-30` docstring, `:55-67` dance)
- Modify: `tests/unit/hooks/test_sandbox_hookpoints_registered.py` (`:3-4` docstring, `:26-31` helper)
- Modify: `tests/unit/security/test_sandbox_refusal_audit.py` (`:165-186` stub, `:216` use)

**Interfaces:**

- Consumes: Task 1's `declare_hookpoints`.
- Produces: nothing new.

- [ ] **Step 1: Re-key the map**

Read `src/alfred/hooks/_known_hookpoints.py:39-41` first and confirm the dict key
names the **declaring module** (it does — the sync test imports
`KNOWN_HOOKPOINTS.keys()` at `:47-48`). Then rename `"alfred.supervisor.core"` →
`"alfred.supervisor.hookpoints"`, keeping every hookpoint name and inline comment.

- [ ] **Step 2: Correct the now-false comment above the dict**

`_known_hookpoints.py:47-55` asserts the supervisor's hookpoints are "registered
inside `Supervisor._register_hookpoints` rather than a module-level
`declare_hookpoints()`" and that "the sync test reaches them via
`Supervisor._register_hookpoints(object())`". After Task 1 **both halves are
false**. Rewrite it to state what is now true: a `declare_hookpoints` function
exists and the boot seam calls it; core-010 still forbids the module-bottom call.

Leaving it is not an option — this PR's subject is declaration drift, and this repo
has six recorded incidents of exactly this shape (spec §12).

- [ ] **Step 3: Retire the `_StubSupervisor` dance — all three sites**

The dance calls an unbound method with a fake `self` purely to reach a tuple. It
existed only because the hookpoints were not boot-declarable. Task 1 retires the
reason; retire all three uses:

1. `tests/unit/hooks/test_known_hookpoints_sync.py:55-67` — replace the stub class
   and `Supervisor._register_hookpoints(_StubSupervisor())` with:

```python
    from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor

    declare_supervisor()
```

   Also fix its module docstring (`:23-30`), which repeats the false "registers its
   **six** hookpoints inside `Supervisor._register_hookpoints`" claim.
2. `tests/unit/hooks/test_sandbox_hookpoints_registered.py:26-31` — the
   `_fresh_registry_with_supervisor_hookpoints` helper. Same replacement. Fix its
   `:3-4` docstring ("PR-S4-6 ships **three** supervisor hookpoints, registered
   inside `Supervisor._register_hookpoints`").
3. `tests/unit/security/test_sandbox_refusal_audit.py:165-186` + `:216` — the
   `_StubSupervisor` class and its two users. Same replacement.

None of these *break* (the delegation reads no `self` state, so the unbound call
keeps working) — but leaving two behind means the next reader finds contradictory
precedents for the same question.

- [ ] **Step 4: Reconcile the ADR-0051-premise comment**

`tests/unit/security/test_sandbox_refusal_audit.py:145-162` is a comment block
pinning the ADR-0051-(B) premise — that dispatch happens post-`Supervisor`. **That
block is CORRECT and must stay.** Rev 1 of this plan contradicted it; rev 2 does
not. If anything, extend it with a pointer: PR2 changes this, and PR1 is the
prerequisite. Do not delete it.

- [ ] **Step 5: Run**

Run: `uv run pytest tests/unit/hooks tests/unit/security/test_sandbox_refusal_audit.py -q`
Expected: all pass.

- [ ] **Step 6: Prove the sync guard still bites**

Add `"supervisor.bogus.drift"` to the `"alfred.supervisor.hookpoints"` tuple in
`_known_hookpoints.py`; re-run the sync test. Expected: **FAIL**. Remove it; re-run.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/hooks/_known_hookpoints.py tests/unit/hooks/ tests/unit/security/test_sandbox_refusal_audit.py
git commit -m "refactor(hooks): #443 re-key the supervisor drift map and retire the stub dance"
```

---

### Task 3: Full gates + PR

**Files:** none — verification only.

- [ ] **Step 1: Run every gate**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
uv run pytest tests/adversarial -q
uv run pytest tests/integration -q
```

Check `$?` explicitly after each — do **not** pipe to `tail`.

The macOS integration lane is flaky **under load**. If a failure looks load-shaped,
re-run that file **in isolation** before believing it is a regression; trust the
Linux CI lanes.

- [ ] **Step 2: i18n drift check**

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d locale -l en
uv run pybabel compile -d locale
```

No `t()` strings are added, but a **line-shifting edit re-stales the `#:` refs** —
re-run and commit the churn. Never `--omit-header`.

- [ ] **Step 3: Markdown lint**

```bash
npx -y markdownlint-cli2@0.22.1 "docs/**/*.md"
```

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin fix/443-boot-time-quarantine-health-check
```

The PR body **must** say, accurately:

- This is **PR1 of two** for #443. It is a **prerequisite**, not a bug fix.
- **core-001 is latent, not live** — ADR-0051:81-89 records that it is moot for the
  current call site. PR2's in-spawn handshake activates it.
- It **unblocks #444**, whose body names this fix.
- No behavioural change beyond *when* declaration happens.
- The deviation: ten hookpoints moved, not the spec's four — because §10's two
  deliverables ("extract the four" + "drop the stub dance") are incompatible at 4/6.
- The tuple is function-local **on purpose** (drift-resolver shape).
- **Do not claim it closes a live fail-open.**

- [ ] **Step 5: Review**

Full `/review-pr` fleet — **security always**. UAT is not applicable (no operator
surface). Then CodeRabbit CLI (`--base origin/main`; local main is stale) **and**
cloud — they catch disjoint bugs and neither is the last word. Resolve every thread.
Merge with a plain `gh pr merge --rebase`. **Never `--admin`.** Do not arm `--auto`
while anything Critical is open.

---

## Self-Review

**Spec coverage.** Spec §6.2's fix (existing seam, not a new site) → Task 1 Steps
3-5. core-010 → Global Constraints + the publisher docstring. §10's re-key → Task 2
Step 1. §10's stub retirement → Task 2 Step 3 (all three sites). §12's false
docstrings → Task 1 Step 4 + Task 2 Step 2.

**Deferred to PR2, deliberately:** the two-frame handshake, the probe hello, the
ADR-0051 amendments, and the whole corpus (021 renumbered) — its threat is not
reachable until PR2.

**Spec corrections this rev forces (fold into the spec):** §6.2's "a live
hard-rule-#7 defect" and §10's "converts core-001 from a silent fail-open into a
fixed one" are both **false** and must be restated as latent-activated-by-PR2.

**Placeholders.** One intentional: the publisher's tuple body and import spellings
say *copy verbatim from `core.py:1063-1064` and `:1075-1123`*. Deliberate —
retyping trust-tier values is how a frozenset silently widens.

**Type consistency.** `declare_hookpoints(registry: HookRegistry | None = None) ->
None` matches `comms_mcp/hookpoints.py:53`. `registry.hookpoint_meta` verified at
`registry.py:744`; `HookpointMeta.fail_closed` verified. `HookRegistry(gate=...)`
verified at `registry.py:515-522` — rev 1 checked the accessor and never the
constructor two lines above it.
