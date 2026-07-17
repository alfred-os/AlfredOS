# #443 PR1 — supervisor hookpoint declaration into the boot seam

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the supervisor a proper boot-time hookpoint publisher so
`supervisor.plugin.sandbox_refused` is declared *before* the quarantine child is
spawned — closing core-001, a live CLAUDE.md hard-rule-#7 silent fail-open.

**Architecture:** Extract the supervisor's hookpoint tuple into a new
`declare_hookpoints(registry)` publisher at `src/alfred/supervisor/hookpoints.py`,
register it in the existing `hooks/boot.py:_declare_all_subsystem_hookpoints`
seam, and have `Supervisor._register_hookpoints` delegate to it. **One tuple, two
callers** — drift becomes structurally impossible. No module-bottom call (core-010).

**Tech Stack:** Python 3.14+, pytest, `alfred.hooks` registry.

## Global Constraints

- **No module-bottom `declare_hookpoints()` call** for the supervisor. core-010
  (`supervisor/core.py:1023-1028`) rejected import-time registration: pytest
  collects every test module's imports before any fixture runs, so publisher
  metadata would persist across tests expecting a clean registry. Add the
  *function*; never the import-time *call*. Every other publisher has both; the
  supervisor gets only the function.
- **One tuple.** `_register_hookpoints` MUST delegate, never keep its own copy.
- **`register_hookpoint` is idempotent on equal metadata, strict on drift**
  (`hooks/registry.py:587`). Drift is compared **by value** — `registry.py:734`
  does `stored != new_meta` on a dataclass with eagerly-normalized frozensets.
  `core.py:1035-1038`'s "SAME frozenset objects" is stricter than the code needs;
  do not treat identity as required.
- **Touches `src/alfred/security/`** (`sandbox_refusal_audit.py` is the publisher
  of `sandbox_refused`) → **the adversarial suite is release-blocking**:
  `uv run pytest tests/adversarial`.
- **`make check` before every push.** `make ... | tail` masks the exit code.
- **Commit subjects need a literal `#443` AFTER the colon** (the
  `Conventional commit format` required check).
- **i18n:** this PR adds no operator-facing strings. structlog event keys are not
  `t()` scope.

## Why this is worth its own PR

core-001 is live on main today. Chain, verified @ `967d8e2e`:

- spawn at `_commands.py:658`; `Supervisor(...)` at `:783` — **125 lines later**
- `supervisor.plugin.sandbox_refused` declared **only** at `supervisor/core.py:1089`
  via `core.py:307`
- `strict_declarations` defaults **True** (`hooks/registry.py:521`)
- `invoke()` on an undeclared hookpoint raises `HookError` (`hooks/invoke.py:1439`)
- `SandboxRefusalAuditor.record()` writes the row (`sandbox_refusal_audit.py:53-65`)
  then **raises**; `_record_launcher_refusals` catches it and logs
  `refusal_record_failed` (`quarantine_child_io.py:648-652`)

**The fail-closed T0 hookpoint never fires on the one path whose purpose is to
trip quarantine** — and because `record()` appends-then-invokes **per row** inside
the `for` at `:51` while the caller catches at the call level, **only the first
row is ever written**. Rows 2..N are silently dropped.

This PR fixes that independently of #443's A/B question and **unblocks #444**.

## Deviation from the spec (flag at plan review)

Spec §10 says "extract the **four** sandbox/boot tuples". This plan moves **all
ten**. Splitting 4-at-boot / 6-in-`__init__` yields **two tuples** and reinstates
the drift this epic keeps shipping (#432 was a vocab drift guard; #434-436 were
false-docstring drift). One tuple with two callers is the architect's own stated
principle. Declaring the other six earlier is safe: idempotent, strictly earlier,
no new dispatch.

## File Structure

- **Create** `src/alfred/supervisor/hookpoints.py` — the single tuple + the
  `declare_hookpoints(registry=None)` publisher. One responsibility: *declare the
  supervisor's hookpoints*. Mirrors the `comms_mcp/hookpoints.py` naming
  convention.
- **Modify** `src/alfred/supervisor/core.py:1018-1132` — `_register_hookpoints`
  becomes a delegation; correct the "six hookpoints" docstring (there are ten).
- **Modify** `src/alfred/hooks/boot.py:81-105` — one import + one call.
- **Modify** `src/alfred/hooks/_known_hookpoints.py:76-92` — re-key the group.
- **Modify** `tests/unit/hooks/test_known_hookpoints_sync.py:55-67` — drop the
  `_StubSupervisor` unbound-call dance.
- **Create** `tests/unit/supervisor/test_hookpoints_publisher.py`
- **Create** `tests/adversarial/sandbox_escape/sbx_2026_021_*.yaml` + its leg.

---

### Task 1: The publisher module

**Files:**

- Create: `src/alfred/supervisor/hookpoints.py`
- Test: `tests/unit/supervisor/test_hookpoints_publisher.py`

**Interfaces:**

- Consumes: `alfred.hooks.registry.HookRegistry`, `get_registry`;
  `alfred.hooks.SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS`;
  `alfred.security.tiers.T0` (import exactly as `supervisor/core.py:1066-1132`
  does — read that block first and copy the import spellings verbatim).
- Produces: `SUPERVISOR_HOOKPOINTS: tuple[...]` and
  `declare_hookpoints(registry: HookRegistry | None = None) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/supervisor/test_hookpoints_publisher.py
"""The supervisor is a boot-declarable hookpoint publisher (#443 PR1, core-001)."""

from __future__ import annotations

from alfred.hooks.registry import HookRegistry
from alfred.supervisor.hookpoints import SUPERVISOR_HOOKPOINTS, declare_hookpoints


def test_declare_hookpoints_registers_every_supervisor_hookpoint() -> None:
    """Every entry in the tuple lands in the passed registry."""
    registry = HookRegistry()

    declare_hookpoints(registry)

    for name, *_rest in SUPERVISOR_HOOKPOINTS:
        assert registry.hookpoint_meta(name) is not None, f"{name} not declared"


def test_sandbox_refused_is_fail_closed_t0() -> None:
    """core-001's target: the fail-closed T0 row must be declarable at boot.

    Pinned by value, not by re-reading the tuple: a test that asks the tuple
    what the tuple says kills zero mutants.
    """
    registry = HookRegistry()

    declare_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None
    assert meta.fail_closed is True


def test_declare_hookpoints_is_idempotent() -> None:
    """Re-declaration on equal metadata is a no-op, not a drift raise.

    Load-bearing: Supervisor.__init__ re-declares after the boot seam already did.
    """
    registry = HookRegistry()

    declare_hookpoints(registry)
    declare_hookpoints(registry)  # must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/supervisor/test_hookpoints_publisher.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.supervisor.hookpoints'`

- [ ] **Step 3: Write the implementation**

First read `src/alfred/supervisor/core.py:1018-1132` in full. Move the tuple
**verbatim** — every entry, every comment. Do not retype the values; cut and paste
so a transcription typo cannot silently change a trust tier.

`declare_hookpoints` must NOT have a module-bottom call (core-010). Give the
module a docstring saying so, and why, or a future contributor will "fix" the
omission.

```python
# src/alfred/supervisor/hookpoints.py
"""Boot-declarable hookpoint publisher for the supervisor (#443 PR1).

Extracted from ``Supervisor._register_hookpoints`` so the supervisor can be a
first-class publisher in ``alfred.hooks.boot._declare_all_subsystem_hookpoints``
— whose docstring requires that every publisher register there so its hookpoints
are declarable at boot.

**core-001**: ``supervisor.plugin.sandbox_refused`` is dispatched by
``SandboxRefusalAuditor`` from the quarantine-child spawn at
``cli/daemon/_commands.py:658`` — 125 lines BEFORE ``Supervisor(...)`` at ``:783``.
While the tuple lived only in ``__init__``, that dispatch hit an undeclared
hookpoint under ``strict_declarations`` and raised ``HookError``, which
``_record_launcher_refusals`` demoted to a ``refusal_record_failed`` log line: the
fail-closed T0 hookpoint never fired on the one path meant to trip quarantine.

**No module-bottom ``declare_hookpoints()`` call — deliberately.** core-010
(``supervisor/core.py``) rejected import-time registration for these hookpoints:
pytest collects every test module's imports before any fixture runs, so the
metadata would persist across tests that expect a clean registry. The boot seam
calls this explicitly instead; that is the shape core-010 wants. Do not add an
import-time call.

``Supervisor._register_hookpoints`` delegates here, so this tuple has two callers
and exactly one definition — drift is structurally impossible.
"""

from __future__ import annotations

# NOTE: copy the import block verbatim from supervisor/core.py's module header —
# SYSTEM_ONLY_TIERS / SYSTEM_OPERATOR_TIERS / T0 / TrustTier / HookRegistry /
# get_registry. Match its spellings exactly.

SUPERVISOR_HOOKPOINTS: tuple[
    tuple[str, frozenset[str], frozenset[str], bool, type[TrustTier]], ...
] = (
    # <-- the ten entries, moved VERBATIM from supervisor/core.py:1075-1123,
    #     comments included.
)


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register every supervisor hookpoint.

    Idempotent on equal metadata and strict on drift
    (``HookRegistry.register_hookpoint``), so the boot seam and
    ``Supervisor.__init__`` may both call it.

    Args:
        registry: Optional override; defaults to the active singleton.
    """
    target = get_registry() if registry is None else registry
    for name, subscribable_tiers, refusable_tiers, fail_closed, carrier_tier in (
        SUPERVISOR_HOOKPOINTS
    ):
        target.register_hookpoint(
            name=name,
            subscribable_tiers=subscribable_tiers,
            refusable_tiers=refusable_tiers,
            fail_closed=fail_closed,
            carrier_tier=carrier_tier,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/supervisor/test_hookpoints_publisher.py -v`
Expected: 3 passed.

The accessor is `HookRegistry.hookpoint_meta(name) -> HookpointMeta | None`
(`hooks/registry.py:744`) — verified, not assumed. There is no `get_hookpoint`.

- [ ] **Step 5: Prove the test is non-vacuous**

Delete the `sandbox_refused` entry from `SUPERVISOR_HOOKPOINTS`; re-run.
Expected: `test_declare_hookpoints_registers_every_supervisor_hookpoint` still
PASSES (it iterates the tuple — a tautological oracle), while
`test_sandbox_refused_is_fail_closed_t0` FAILS.

**This is the point.** The first test asks the tuple what the tuple says and kills
zero mutants; the second names the row independently. Restore the entry. Keep
both, but understand which one is load-bearing —
`domain_a_test_that_asks_the_code_if_the_code_is_right`.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/supervisor/hookpoints.py tests/unit/supervisor/test_hookpoints_publisher.py
git commit -m "feat(supervisor): #443 add a boot-declarable hookpoint publisher"
```

---

### Task 2: Delegate `_register_hookpoints`; correct the count docstring

**Files:**

- Modify: `src/alfred/supervisor/core.py:1018-1132`
- Test: `tests/unit/supervisor/test_hookpoints_publisher.py`

**Interfaces:**

- Consumes: `alfred.supervisor.hookpoints.declare_hookpoints` (Task 1).
- Produces: no signature change — `Supervisor._register_hookpoints(self) -> None`.

- [ ] **Step 1: Write the failing test**

```python
def test_supervisor_register_hookpoints_delegates_to_the_publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One tuple, two callers: __init__ must not keep a second copy.

    Patches the publisher and asserts _register_hookpoints routes through it —
    so a future edit that re-inlines the tuple fails here.
    """
    import importlib

    calls: list[object] = []
    mod = importlib.import_module("alfred.supervisor.hookpoints")
    monkeypatch.setattr(mod, "declare_hookpoints", lambda registry=None: calls.append(registry))

    from alfred.supervisor.core import Supervisor

    class _StubSupervisor:
        """No-state stub — _register_hookpoints reads no self state."""

    Supervisor._register_hookpoints(_StubSupervisor())  # type: ignore[arg-type]

    assert len(calls) == 1, "_register_hookpoints did not delegate to the publisher"
```

Note the `importlib.import_module` + two-arg `setattr`: patching a lazily-imported
symbol re-exported from a package `__init__` via the dotted-string form resolves to
the shadowing function, not the module attribute. This repo has been bitten by that
(`procedural_433_launcher_refusal_audit`).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/supervisor/test_hookpoints_publisher.py::test_supervisor_register_hookpoints_delegates_to_the_publisher -v`
Expected: FAIL — `assert 0 == 1` (the inlined tuple never calls the publisher).

- [ ] **Step 3: Replace the body with a delegation**

Delete the inlined `hookpoints = (...)` tuple and its `for` loop. Keep the
per-hookpoint trust-tier rationale comments — move them into
`supervisor/hookpoints.py` beside the entries they explain (Task 1), do not delete
them.

```python
    def _register_hookpoints(self) -> None:
        """Register every supervisor hookpoint with the global registry.

        Delegates to :func:`alfred.supervisor.hookpoints.declare_hookpoints` —
        the single definition, also called by the boot seam
        (``alfred.hooks.boot._declare_all_subsystem_hookpoints``) so
        ``supervisor.plugin.sandbox_refused`` is declared BEFORE the
        quarantine-child spawn dispatches it (#443 PR1, core-001).

        Kept as a method (rather than dropping it for the boot call alone)
        because tests and non-boot callers construct ``Supervisor`` directly and
        must still find the hookpoints declared. ``register_hookpoint`` is
        idempotent on equal metadata, so the double declaration is a no-op.

        core-010 still holds: the publisher exposes a FUNCTION, not a
        module-import side effect.
        """
        from alfred.supervisor.hookpoints import declare_hookpoints

        declare_hookpoints()
```

Also fix the stale count: `core.py:1021` says "the supervisor's **six**
hookpoints"; the tuple has **ten**. That false docstring is one of six found in
this subsystem (spec §12) — do not leave it behind in a PR whose whole subject is
declaration drift.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/supervisor tests/unit/hooks -v`
Expected: all pass. If a test asserts the exact `_register_hookpoints` body or
patches a `core.py`-local symbol, update it to target the publisher.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/supervisor/core.py tests/unit/supervisor/test_hookpoints_publisher.py
git commit -m "refactor(supervisor): #443 delegate _register_hookpoints to the publisher"
```

---

### Task 3: Register in the boot seam — the actual core-001 fix

**Files:**

- Modify: `src/alfred/hooks/boot.py:81-105`
- Test: `tests/unit/hooks/test_boot_registry_declares_supervisor.py` (create)

**Interfaces:**

- Consumes: `alfred.supervisor.hookpoints.declare_hookpoints` (Task 1).
- Produces: no signature change.

- [ ] **Step 1: Write the failing test**

This is the core-001 oracle. It asserts the *dispatch works*, not that a name is
present — a presence-only assertion passes straight through the bug.

```python
# tests/unit/hooks/test_boot_registry_declares_supervisor.py
"""core-001: sandbox_refused must be declarable BEFORE Supervisor exists (#443 PR1)."""

from __future__ import annotations

import pytest

from alfred.hooks.boot import _declare_all_subsystem_hookpoints
from alfred.hooks.registry import HookRegistry


def test_boot_seam_declares_sandbox_refused_without_a_supervisor() -> None:
    """The boot registry must carry the fail-closed T0 row with no Supervisor built.

    Before #443 PR1 the ONLY declarer was Supervisor.__init__ (core.py:307), which
    runs 125 lines after the quarantine-child spawn dispatches this hookpoint —
    so the dispatch raised HookError and was demoted to a log line.
    """
    registry = HookRegistry()

    _declare_all_subsystem_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None, "core-001: sandbox_refused undeclared at boot"
    assert meta.fail_closed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/hooks/test_boot_registry_declares_supervisor.py -v`
Expected: FAIL — `core-001: sandbox_refused undeclared at boot`.

**If it PASSES, stop.** Something else already declares it and this plan's premise
is wrong — report before proceeding.

- [ ] **Step 3: Add the import + call**

In `_declare_all_subsystem_hookpoints`, add to the function-local import block
(alphabetical, matching the existing style) and to the call list:

```python
    from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor
```

```python
    declare_supervisor(registry)
```

Function-local imports are the established shape here — they avoid an import cycle
(`hooks` ← `supervisor` ← `hooks`). Do not hoist to module level.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/hooks/test_boot_registry_declares_supervisor.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full hooks + supervisor + daemon-boot suites**

Run: `uv run pytest tests/unit/hooks tests/unit/supervisor tests/unit/cli/daemon -q`
Expected: all pass. A test asserting the boot registry's exact hookpoint count
will need its expected value updated — that is a real signal, not noise: confirm
the delta is exactly the supervisor's ten.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/hooks/boot.py tests/unit/hooks/test_boot_registry_declares_supervisor.py
git commit -m "fix(hooks): #443 declare supervisor hookpoints at boot, closing core-001"
```

---

### Task 4: Re-key the drift map; drop the `_StubSupervisor` dance

**Files:**

- Modify: `src/alfred/hooks/_known_hookpoints.py:76-92`
- Modify: `tests/unit/hooks/test_known_hookpoints_sync.py:55-67`

**Interfaces:**

- Consumes: Tasks 1-3.
- Produces: nothing new.

- [ ] **Step 1: Read the map's contract**

Read `src/alfred/hooks/_known_hookpoints.py:1-75`. The dict key names the
**declaring module**. Since the declaration moved, the key
`"alfred.supervisor.core"` is now false. Confirm this from the header before
editing — if the key means something else, stop and report.

- [ ] **Step 2: Re-key the group**

Rename the key `"alfred.supervisor.core"` → `"alfred.supervisor.hookpoints"`.
Keep every hookpoint name and comment in the tuple unchanged.

- [ ] **Step 3: Drop the stub dance**

In `tests/unit/hooks/test_known_hookpoints_sync.py`, replace the
`_StubSupervisor` + unbound `Supervisor._register_hookpoints(...)` call (lines
~55-67, including its seven-line justification comment) with the real publisher:

```python
    from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor

    declare_supervisor()
```

The stub existed **only** because these hookpoints were not boot-declarable. It is
a test smell the fix retires — calling an unbound method with a fake `self` to
reach a tuple. Deleting it is part of the deliverable.

- [ ] **Step 4: Run the sync test**

Run: `uv run pytest tests/unit/hooks/test_known_hookpoints_sync.py -v`
Expected: PASS.

- [ ] **Step 5: Prove the drift guard still bites**

Add a fake entry `"supervisor.bogus.drift"` to the `"alfred.supervisor.hookpoints"`
tuple in `_known_hookpoints.py`; re-run the sync test.
Expected: FAIL.
Then remove it and re-run. Expected: PASS.

A guard's non-vacuity must be **proven by breaking the guarded code**, never
asserted (`domain_guard_completeness_and_oracle_independence`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/hooks/_known_hookpoints.py tests/unit/hooks/test_known_hookpoints_sync.py
git commit -m "refactor(hooks): #443 re-key the supervisor drift map to its publisher"
```

---

### Task 5: `sbx-2026-021` — the core-001 adversarial oracle

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_021_sandbox_refused_dispatch_demoted_pre_supervisor.yaml`
- Modify: whichever leg executes the corpus — read
  `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` first and
  follow it exactly. It iterates the YAML's own variant lists; do **not** add a
  second hardcoded copy (the #428 lesson).

**Interfaces:**

- Consumes: Tasks 1-3.
- Produces: corpus id 021 (001-020 taken).

**Scope note — deviation from spec §9.** The spec described `sbx-2026-021` as
`boot_barrier_absent_launcher_refusal_reaches_runtime`, asserting
`QuarantineChildSpawnError` **from the spawn**. That is PR2 behaviour (it needs the
handshake). PR1's corpus entry is scoped to core-001 alone: **the dispatch is
silently demoted when the hookpoint is undeclared.** PR2 renumbers its entries
from 022. Fix the spec's §9 numbering when PR2 lands.

- [ ] **Step 1: Read the corpus conventions**

```bash
sed -n '1,60p' tests/adversarial/sandbox_escape/sbx_2026_018_launcher_refusal_row_injection.yaml
sed -n '1,80p' tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py
```

Match `id / category / threat / ingestion_path / payload / expected_outcome /
provenance / references` exactly.

- [ ] **Step 2: Write the failing corpus entry + leg**

The threat: *a `sandbox_refused` dispatch against a registry that has not declared
the hookpoint raises `HookError`, which `_record_launcher_refusals` swallows into
`refusal_record_failed` — so the fail-closed T0 hookpoint never fires and rows
2..N are never written.*

The oracle MUST assert the **dispatch fired**, not that a row exists. `record()`
appends at `:53-65` *then* invokes at `:73` — so a row-only assertion passes
straight through the bug. Assert a subscriber on
`supervisor.plugin.sandbox_refused` actually ran.

Derive "the dispatch fired" from the **subscriber**, never from re-reading the
registry's own predicate — an oracle that reuses the implementation predicate kills
zero mutants (`domain_a_test_that_asks_the_code_if_the_code_is_right`).

Use `structlog.testing.capture_logs()` filtering `e["event"]` to assert
`refusal_record_failed` is **absent** — structlog does **not** land in `caplog`, so
a `caplog`-based assertion here is vacuous.

- [ ] **Step 3: Run it against the PRE-fix code to verify it fails**

```bash
git stash
uv run pytest tests/adversarial/sandbox_escape -k 2026_021 -v
git stash pop
```

Expected: FAIL (or error on the missing module) — proving the oracle bites.
**If it passes against pre-fix code, the oracle is vacuous. Rewrite it.**

- [ ] **Step 4: Run against the fixed code**

Run: `uv run pytest tests/adversarial/sandbox_escape -k 2026_021 -v`
Expected: PASS.

- [ ] **Step 5: Run the whole adversarial suite (release-blocking)**

Run: `uv run pytest tests/adversarial -q`
Expected: all pass. This PR touches `src/alfred/security/`, so this is mandatory,
not optional.

Also run the density check: `uv run pytest tests/adversarial/test_corpus_density.py -q`

- [ ] **Step 6: Commit**

```bash
git add tests/adversarial/sandbox_escape/
git commit -m "test(sandbox): #443 pin the core-001 dispatch demotion as sbx-2026-021"
```

---

### Task 6: Full gates + PR

**Files:** none — verification only.

- [ ] **Step 1: Run every gate**

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
uv run pytest tests/adversarial -q
uv run pytest tests/integration -q
```

Check `$?` explicitly after each — do **not** pipe to `tail`, it masks the exit
code (`feedback_make_check_before_push`).

The macOS integration lane is flaky **under load** (mass testcontainers setup
errors). If a failure looks load-shaped, re-run that file **in isolation** before
believing it is a regression; trust the Linux CI lanes.

- [ ] **Step 2: i18n drift check**

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d locale -l en
uv run pybabel compile -d locale
```

This PR adds no `t()` strings, but a **line-shifting edit re-stales the `#:` refs**
— re-run and commit the churn if the catalog moves. Never `--omit-header`.

- [ ] **Step 3: Markdown lint**

```bash
npx -y markdownlint-cli2@0.22.1 "docs/**/*.md"
```

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin fix/443-boot-time-quarantine-health-check
```

PR body must state: this closes core-001 (a live hard-rule-#7 silent fail-open);
it is PR1 of two for #443; it **unblocks #444**; it makes no behavioural change
beyond *when* declaration happens; and the deviation above (ten tuples moved, not
four) with its rationale.

- [ ] **Step 5: Review**

Full `/review-pr` fleet — **security always**, plus UAT is not applicable here (no
operator surface). Then CodeRabbit CLI (`--base origin/main`; local main is stale)
**and** cloud — they catch disjoint bugs and neither is the last word. Resolve
every thread. Merge with a plain `gh pr merge --rebase`. **Never `--admin`.**

---

## Self-Review

**Spec coverage.** §6.2's fix (the existing seam, not a new site) → Tasks 1+3.
§6.2's core-010 constraint → Global Constraints + Task 1 Step 3. §10's re-key →
Task 4. §10's `_StubSupervisor` retirement → Task 4 Step 3. §10's "assert the
dispatch, not the row" → Task 5 Step 2. §12's `core.py:1021` false docstring →
Task 2 Step 3.

**Deliberately deferred to PR2** (documented above, not gaps): the two-frame
handshake (§5), the probe hello (§6.1), the ADR-0051 amendments (§8), corpus
022/023/024, and the `daemon_runtime.py:324-326` / `quarantine_child_io.py:802-805`
docstring corrections — PR1 does not touch those files.

**Placeholders.** None. The one intentional gap is Task 1 Step 3's import block
and tuple body, which say *copy verbatim from `core.py:1066-1132`* — deliberate:
retyping trust-tier values from memory is exactly how a frozenset silently
widens.

**Type consistency.** `declare_hookpoints(registry: HookRegistry | None = None) ->
None` is used identically in Tasks 1, 2, 3, 4. `SUPERVISOR_HOOKPOINTS` is
referenced only in Tasks 1 and 4. Accessor `registry.hookpoint_meta` was verified against
`hooks/registry.py:744` while writing this plan — an earlier draft used a
`get_hookpoint` that does not exist.
