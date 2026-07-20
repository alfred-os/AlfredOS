# #472 — CodeRabbit outside-diff-range findings from #464 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four CodeRabbit "outside diff range" findings that #464 merged without — three Major, one Minor — all of the same family: a cleanup, teardown, or budget path where something escapes its bound and destroys a typed outcome.

**Architecture:** Two PRs off `main`. **PR-A** = findings 1, 4, 3 — three small fixes that make a bound real or stop a cleanup destroying an outcome; fast lane. **PR-B** = finding 2, the cancellation-safe revoke — the only one touching a Protocol, adding a seam method, resting on a structured-concurrency argument, and needing an ADR-0052 amendment plus docstring/runbook updates. Split because a reviewer must hold PR-B's cancellation-delivery-count and `asyncio.timeout.__aexit__` reasoning in their head, and the #472 post-mortem is that a large PR's findings get skimmed. #472 stays open until both land.

**Tech Stack:** Python 3.14.6+, asyncio, pytest, structlog. `mypy --strict` + `pyright` (neither type-checks `tests/`). `src/alfred/security/` is touched in both PRs, so the adversarial suite is release-blocking for both.

## Provenance

This plan was reviewed pre-execution by three lanes (test-engineer, core-engineer, architect). Their corrections are folded in. The most consequential: finding 4's fix target was wrong in the source issue *and* my first draft (see PR-A Task 2); finding 3's fix was a clean-shutdown regression as first drafted (PR-A Task 3); and the CPython `asyncio.timeout.__aexit__` conversion is **not** unconditional — case (c) reaches the new `CancelledError` arm (PR-B Task 3, "THE TRAP"). All CPython mechanics below were verified empirically on 3.14.6.

## Global Constraints

- **100% line + branch coverage** on every module under `src/alfred/security/` and on `src/alfred/cli/daemon/_commands.py` (per-module CI `--fail-under=100` gates). CI runs 47 such gate invocations; **`make check` runs none of them** (tracked as #474). Do **not** report "gates green" on `make check` alone — run the per-module coverage command in each PR's final task.
- **Neither `mypy`, `pyright`, nor `issubclass` will catch a test double missing a new Protocol method** — mypy/pyright do not type-check `tests/`, and `runtime_checkable` `issubclass` checks method *presence* only at the one call site that uses it. A missing `abort()` on a double is therefore a **silent** hole. PR-B Task 2 adds a structural guard for this.
- **HARD #7 — no silent failures in security paths.** Every suppression added here logs loud first; every emit inside a teardown/cancel path is itself `contextlib.suppress(Exception)`-wrapped so an emit failure cannot escape or preempt the real control flow (the `_terminate_and_reap` precedent).
- **`provider_dispatch.py` stays egress-free by documented intent.** Its docstring (`:207-214`) types `source` as `Any` to keep `brokered_egress`'s httpx/ssl/socket closure off its graph. **This is intent, not an enforced gate** — `test_quarantine_child_import_closure.py`'s `_FORBIDDEN_ROOTS` does not list any egress module, and the any-scope oracle is deferred to #465. The `:207-214` clause claiming an import "would trip the child-import-closure gate" is therefore **false** and is corrected in PR-A Task 2. PR-A's chosen fix needs no `provider_dispatch` import regardless.
- **structlog does NOT land in `caplog`.** Assert log events via `structlog.testing.capture_logs()` filtering `e["event"]`. A `caplog` assertion on a structlog event is vacuous.
- **A test oracle must not reuse the implementation's own predicate**, and every new branch needs a test that *fails when the branch is reverted*. Mutation-check each test explicitly (a named step). Where a fix adds a defensive `except`, add a **negative** assertion that the defensive arm did *not* fire on the happy path — otherwise the defensive arm silently absorbs a broken test double and the test proves nothing.
- **Platform guards go on a `@pytest.mark.skipif` DECORATOR**, never a runtime skip inside a helper.
- **Conventional commits** need a literal `#472` *after* the colon in every commit subject.
- **Never `git add -A`** — add named paths only.
- No i18n catalog change: structlog event keys are not `t()` scope; no new operator-facing `t()` string is added.

---

## File Structure

| File | Responsibility | PR / Finding |
| --- | --- | --- |
| `src/alfred/security/quarantine_child/provider_dispatch.py` | Cap retry backoff at remaining budget; loud log on the `ProviderUnavailableError` arm; correct 3 false comments | PR-A / 1, 4 |
| `src/alfred/security/quarantine_child/brokered_egress.py` | Map `InvalidAttemptBudgetError` → `ProviderUnavailableError` in `bind()` | PR-A / 4 |
| `src/alfred/cli/daemon/_commands.py` | Sentinel + conditional re-raise so `supervisor.stop()` can't mask a boot refusal, nor silence a clean-shutdown failure | PR-A / 3 |
| `tests/unit/quarantine/test_quarantined_extractor_dispatch.py` | Backoff-budget spy test; budget-exhaustion split test | PR-A / 1, 4 |
| `tests/unit/cli/daemon/test_daemon_boot_reap_finally.py` | 3 supervisor-stop arms | PR-A / 3 |
| `docs/adr/0052-real-quarantine-child-golive.md` | Dated note: backoff was the one unclamped budget term (PR-A); revoke-cancel behaviour change + residuals (PR-B) | PR-A + PR-B |
| `src/alfred/security/quarantine_transport.py` | Cancellation-safe revoke; `ChildIO.abort()`; `_abort_child_now`; docstring | PR-B / 2 |
| `src/alfred/security/quarantine_child_io.py` | `_SubprocessChildIO.abort()` | PR-B / 2 |
| `tests/unit/security/test_quarantine_transport.py`, `test_quarantine_child_io.py`, `test_quarantine_revocation_metric.py`, `tests/unit/egress/test_broker_audit_wiring.py`, `tests/adversarial/tier_laundering/...`, `tests/unit/cli/daemon/conftest.py` | `abort()` on 7+ doubles; structural guard; tests A–D + residual/idempotency/outer-scope | PR-B / 2 |
| `docs/subsystems/security.md`, `docs/runbooks/quarantine-capability-revoked.md` | New structlog events + zombie triage | PR-B / 2 |

---

## PR-A — findings 1, 4, 3 (three small fixes)

Branch: `472a-budget-and-cleanup-fixes` off `main`.

### Task A1: Cap the retry backoff at the remaining budget (finding 1, Major)

**Files:**

- Modify: `src/alfred/security/quarantine_child/provider_dispatch.py:390-394` (the fix), `:132-136` and `:227-231` (correct now-true comments)
- Test: `tests/unit/quarantine/test_quarantined_extractor_dispatch.py` (extend — this is where the real dispatch fixtures live)

**Interfaces:**

- Consumes: `_MAX_TOTAL_WALL_CLOCK_SECONDS` (20.0), `_BACKOFF_BASE_SECONDS` (0.5), `EXTRACTION_MAX_RETRIES` (2), `deadline_monotonic` (local at `:296`). Both constants are module-global lookups inside the loop, so monkeypatching them bites.
- Produces: behaviour change only.

**Why real, and its true severity.** The backoff sleep at `:394` is computed from `attempt` alone, never clamped to `deadline_monotonic`. An attempt finishing at t=19.9s sleeps 1.0s → return at t=20.9s. Three comments claim the budget is a ceiling (`:136` "Keeps the loop inside the wall-clock budget"; `:227-231` "Total wall-clock ... capped ... Three mechanisms hold that cap"). Worst-case overrun is **≤1.0s** (max backoff is `0.5 × 2¹` after attempt 1), so `child_budget(21) < gateway_handshake(22)` — the ADR-0052 nesting invariant was **never actually violated**. Real, worth fixing, **not a live incident**; the PR body must say so rather than imply a breach.

> **Implementation note (supersedes the sketch below).** The shipped test replaces the real-clock sleep-spy sketched here with a **deterministic `_FakeClock` advanced by each requested sleep** — so `deadline − now` genuinely shrinks between attempts, killing both the uncapped and the wrong-deadline (clamp-against-constant) mutants with **zero wall-clock tolerance** (budget 1.25 / back-offs 0.5, 0.75 are exact in IEEE-754). CodeRabbit flagged the real-clock sketch as flake-prone; the fake clock resolves it. Separately, the `--cov-report=... --cov-branch` commands in this plan are for **local inspection**; the CI gate that *enforces* the 100% threshold is `coverage report --fail-under=100` (add `--cov-fail-under=100` to reproduce enforcement locally).

- [ ] **Step 1: Write the failing test — deterministic sleep-spy oracle**

Append to `tests/unit/quarantine/test_quarantined_extractor_dispatch.py`. Reuse the file's existing fixtures: `_FakeSource` (`:112`, records per-attempt `budgets`, has `capabilities()` and an async-CM `bind()`), `_fake_provider_with_capabilities` (`:96`), `_text_response` (`:163`), `_SCHEMA_JSON` (`:82`). Do **not** monkeypatch `_call_provider`: `_text_response("not json at all")` drives the real path (`_call_provider` → `_validate_response` → `json.loads` raises `JSONDecodeError` → the retry arm at `:376`), and it exercises the mode branch honestly.

The oracle is `(timestamp observed at the real sleep call, delay the implementation actually requested)` — never the `min()` itself. It kills mutants the wall-clock version cannot: clamping against the wrong deadline, dropping `max(0.0, …)`, clamping only on the last attempt.

```python
@pytest.mark.asyncio
async def test_backoff_never_carries_the_loop_past_the_wall_clock_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Total elapsed across retries cannot exceed the budget (#472 finding 1).

    Asserted BEHAVIOURALLY, at the real sleep call site: for every back-off the
    loop requests, (call-time + requested-delay) must land within the budget. A
    test asserting ``min(...)`` appears in the argument would pass against a cap
    computed from the wrong deadline.
    """
    import time as _time

    from alfred.security.quarantine_child import provider_dispatch as pd

    recorded: list[tuple[float, float]] = []
    real_sleep = asyncio.sleep

    async def _spy_sleep(delay: float, *a: object, **kw: object) -> None:
        recorded.append((_time.monotonic(), delay))
        await real_sleep(0)  # yield, burn no wall clock

    monkeypatch.setattr(pd.asyncio, "sleep", _spy_sleep)
    monkeypatch.setattr(pd, "_MAX_TOTAL_WALL_CLOCK_SECONDS", 0.05)

    source = _FakeSource(
        _fake_provider_with_capabilities(
            frozenset({ProviderCapability.NATIVE_CONSTRAINED_GENERATION}),
            _text_response("not json at all"),
        )
    )
    started = _time.monotonic()
    result = await pd.dispatch_extraction(
        content=b"irrelevant t3 body",
        schema_json=_SCHEMA_JSON,
        schema_version=1,
        source=source,
    )

    assert result["kind"] == "typed_refusal"
    assert result["reason"] == "cannot_extract"
    assert recorded, "the retry loop never slept — the test never reached the back-off"
    for t_call, delay in recorded:
        assert delay >= 0.0, f"negative back-off requested: {delay}"
        assert (t_call + delay) - started <= pd._MAX_TOTAL_WALL_CLOCK_SECONDS, (
            f"a {delay:.3f}s back-off at t+{t_call - started:.3f}s would carry the loop "
            f"past the {pd._MAX_TOTAL_WALL_CLOCK_SECONDS}s ceiling"
        )
```

Confirm `ProviderCapability` and the fixtures are importable at the top of that test module (they already are — mirror the existing imports).

- [ ] **Step 2: Run it and verify it FAILS**

```bash
uv run pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py -q -k backoff_never
```

Expected: FAIL — an uncapped `0.5×2⁰=0.5s` back-off requested against a 0.05s budget overshoots. If it errors at construction instead (e.g. `AttributeError` on the source), the fixture wiring is wrong — fix the test before the implementation.

- [ ] **Step 3: Apply the fix**

Replace `provider_dispatch.py:390-394`:

```python
        # Exponential back-off (perf-1 fix). Skip on the last attempt — no next
        # try, the loop is about to exit and the refusal is the next emit.
        if attempt < EXTRACTION_MAX_RETRIES:
            # CLAMPED to the remaining budget (#472 finding 1). Uncapped, the sleep is
            # computed from ``attempt`` alone and can carry the loop PAST
            # ``deadline_monotonic`` — the loop head then refuses, but only after the
            # overrun. A ceiling a back-off can overrun is not a ceiling. ``max(0.0, ...)``
            # normalises an already-breached budget to an explicit zero-sleep yield rather
            # than leaning on ``asyncio.sleep``'s negative-delay short-circuit; the loop
            # head converts it to ``cannot_extract`` on the next pass.
            await asyncio.sleep(
                max(
                    0.0,
                    min(_BACKOFF_BASE_SECONDS * (2**attempt), deadline_monotonic - time.monotonic()),
                )
            )
```

`min`/`max` are expressions, not branches — no new branch to cover. `ruff format` will reflow the argument; paste it and let it.

- [ ] **Step 4: Run and verify PASS**

```bash
uv run pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py -q -k backoff_never
```

- [ ] **Step 5: Mutation-check**

Revert Step 3, re-run → FAIL; re-apply. Record it.

- [ ] **Step 6: Correct the now-true comments**

`:136` — change "Keeps the loop inside the wall-clock budget while giving a thrashing provider time to recover." to note the sleep is clamped to the remaining budget (the back-off no longer *keeps* the loop inside the budget; the clamp does). `:227-231` — "Three mechanisms hold that cap" is now four; add the back-off clamp as the fourth, or reword to "the back-off is itself clamped to the remaining budget". Keep edits minimal and true.

- [ ] **Step 7: Coverage + commit**

```bash
uv run pytest tests/unit --cov=alfred.security.quarantine_child.provider_dispatch \
  --cov-report=term-missing --cov-branch -q
git add src/alfred/security/quarantine_child/provider_dispatch.py \
        tests/unit/quarantine/test_quarantined_extractor_dispatch.py
git commit -m "fix(security): #472 cap extraction back-off at the remaining budget"
```

---

### Task A2: Type budget exhaustion in `bind()` as `provider_unavailable` (finding 4, Minor)

**Files:**

- Modify: `src/alfred/security/quarantine_child/brokered_egress.py:463-469`
- Modify: `src/alfred/security/quarantine_child/provider_dispatch.py:367-375` (add the missing loud log to the existing `ProviderUnavailableError` arm), `:207-214` (correct the false gate claim)
- Test: `tests/unit/quarantine/test_quarantined_extractor_dispatch.py` (or `test_brokered_provider_source.py` for the unit-level `bind()` assertion — put the end-to-end split test with the dispatch tests)

**Interfaces:**

- Consumes: `InvalidAttemptBudgetError` (`brokered_egress.py:81`), `ProviderUnavailableError` (already imported, `brokered_egress.py:57`), `PassedFdBackend.__init__`'s budget guard (`:225-231`).
- Produces: `bind()` raises `ProviderUnavailableError` (not the raw `InvalidAttemptBudgetError`) when the control-fd recv exhausts the attempt budget before the backend is built. Downstream `provider_dispatch` already has a terminal `except ProviderUnavailableError` arm → `provider_unavailable`.

**Why `ProviderUnavailableError`, not `TimeoutError` (correcting the issue AND my first draft).** `_recv_one_fd` already handles the two sibling cases of this exact root cause and maps **both** to `ProviderUnavailableError`: budget spent *before* the recv (`:431-435`) and a recv `TimeoutError` (`:437-441`). `InvalidAttemptBudgetError` is the third member (recv *succeeded* but ate the budget). Its own docstring (`:425-429`) states the rule verbatim: mapping budget exhaustion to `cannot_extract` (what an unmapped `TimeoutError` lands as) is *"laundering an egress fault as a model-output failure ... the err-002 / HARD #7 anti-pattern"* (ADR-0052 C1). So the correct target is `ProviderUnavailableError`, consistent with both siblings, needing **no** `provider_dispatch` import and **no** vocabulary drift. The issue's "catch in `provider_dispatch`" and my draft's "`TimeoutError`" are both wrong.

- [ ] **Step 1: Write the failing split test**

Prove the two adjacent budget-exhaustion paths land on the **same** typed refusal — the split being *absent* is the property. Drive `bind()` directly for the unit assertion, then assert the end-to-end refusal through `dispatch_extraction`.

```python
@pytest.mark.asyncio
async def test_budget_exhausted_by_the_control_recv_is_provider_unavailable() -> None:
    """A recv that eats the whole attempt budget surfaces as provider_unavailable.

    ``PassedFdBackend`` refuses a non-positive budget with
    ``InvalidAttemptBudgetError`` (a ValueError). Raised out of ``__aenter__`` it
    escapes ``dispatch_extraction`` UNTYPED. It must map to the SAME
    ``provider_unavailable`` refusal as its two sibling budget-exhaustion paths in
    ``_recv_one_fd`` (:431, :437) — not ``cannot_extract``, which would launder an
    egress fault as a model-output failure (err-002 / HARD #7, ADR-0052 C1).
    """
```

Construct a `BrokeredProviderSource` whose `_recv_one_fd` returns a dummy fd but consumes the budget before `bind()` builds the backend (mirror the construction idiom in `tests/unit/security/test_brokered_provider_source.py` — reuse its socketpair/`_factory`/fd fixtures; ensure the dummy fd is still reclaimed by the `finally` at `:471-493` and not leaked). Assert `pytest.raises(ProviderUnavailableError)` out of `bind()`, then assert `dispatch_extraction(...)["reason"] == "provider_unavailable"`.

- [ ] **Step 2: Run and verify FAIL** (raises `InvalidAttemptBudgetError`, not `ProviderUnavailableError`).

```bash
uv run pytest tests/unit/quarantine/test_quarantined_extractor_dispatch.py -q -k budget_exhausted
```

- [ ] **Step 3: Apply the fix — in `bind()`**

`brokered_egress.py`, inside `bind()`'s `try` (so the `finally` still reclaims the fd):

```python
            # A budget exhausted by the recv above raises InvalidAttemptBudgetError out of
            # the backend ctor; the finally below reclaims the fd (backend still None).
            # Convert to ProviderUnavailableError HERE (#472 finding 4): raised out of
            # __aenter__ it would escape dispatch_extraction UNTYPED, and mapping it to the
            # cannot_extract an unmapped raise lands as would launder an egress fault as a
            # model-output failure (err-002 / HARD #7, ADR-0052 C1). This is the third
            # sibling of the two budget-exhaustion maps in _recv_one_fd (:431, :437), which
            # both raise ProviderUnavailableError — same fault, same refusal.
            try:
                provider, backend = self._factory.build(
                    fd, budget_seconds=deadline_at - time.monotonic()
                )
            except InvalidAttemptBudgetError as exc:
                raise ProviderUnavailableError(
                    "quarantine child: the attempt budget was exhausted before the provider "
                    "could be built — the control-fd recv consumed it"
                ) from exc
```

- [ ] **Step 4: Add the missing loud log to `provider_dispatch`'s `ProviderUnavailableError` arm**

That arm (`:367-375`) returns silently — a pre-existing HARD #7 loudness gap now shared by three paths. Add a `_log.warning` carrying `attempt` and `remaining_budget_s` (mirror the `TimeoutError` arm's `extraction_deadline_exceeded` shape at `:360-365`), so an operator can distinguish a budget/egress fault from three rejected model responses.

- [ ] **Step 5: Correct the false gate claim** at `provider_dispatch.py:207-214`

Replace "would drag the egress-capable import closure onto this module's graph and trip the child-import-closure gate" with the truth: the module stays egress-free by **documented intent**; the enforcing any-scope oracle does not yet exist (tracked in #465), and the module-scope `test_quarantine_child_import_closure.py` does not forbid egress modules. This is a false-comment fix in a file the PR already edits — fold it, flag it in the PR body.

- [ ] **Step 6: Run, mutation-check, coverage**

```bash
uv run pytest tests/unit/quarantine tests/unit/security -q -k "budget_exhausted or provider_unavailable"
uv run pytest tests/unit --cov=alfred.security.quarantine_child.brokered_egress \
  --cov=alfred.security.quarantine_child.provider_dispatch --cov-report=term-missing --cov-branch -q
```

Revert Step 3, confirm FAIL, re-apply. Confirm no fd leak on the new arm.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child/brokered_egress.py \
        src/alfred/security/quarantine_child/provider_dispatch.py \
        tests/unit/quarantine/test_quarantined_extractor_dispatch.py
git commit -m "fix(security): #472 map attempt-budget exhaustion to provider_unavailable"
```

---

### Task A3: Sentinel-guarded `supervisor.stop()` cleanup (finding 3, Major)

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` — add an `except BaseException` sentinel on the outer boot `try` (around `:989-1028`), and the conditional-re-raise around `supervisor.stop()` (`:1027-1028`)
- Test: `tests/unit/cli/daemon/test_daemon_boot_reap_finally.py` (the real harness — `CliRunner().invoke(daemon_app, ["start"])`, `boot_success_env`, `tmp_path/"daemon.pid"`)

**Interfaces:**

- Consumes: `suppress` (already imported, `:34`), `log` (structlog, `:187`), `_BootRefusedError`. Note `_commands.py:1116` converts `_BootRefusedError` → `typer.Exit(refused.code)` *outside* this try/finally, so the sentinel here captures it as it unwinds.
- Produces: new structlog event `daemon.shutdown.supervisor_stop_failed`.

**Why the bare-suppress the issue proposes is a regression.** `supervisor.stop()` raises **deliberately** on a persistence failure (`core.py` err-002/F5: `SQLAlchemyError` re-raised so the operator sees it) and on an unwritable shutdown audit (HARD #5). On a **clean** shutdown there is no exception in flight, so `stop()` raising is the *only* signal. A bare `with suppress(Exception)` turns that into exit 0 + a structlog line nobody alerts on — the exact masking defect this issue exists to close, reintroduced by its own fix. Suppress **only while unwinding a real failure**.

- [ ] **Step 1: Write three failing tests**

Oracle = `result.exit_code` + the loud row via `capture_logs()`, plus pidfile-gone to guard the #255 non-regression. Three arms for the 100% branch gate:

1. **refusal + `stop()` raises** — `_BootRefusedError` in flight, `stop()` raises `RuntimeError`. Assert `result.exit_code == <refusal code>` (the boot refusal survives, not the RuntimeError), the pidfile is gone, and `capture_logs()` has `daemon.shutdown.supervisor_stop_failed` with `error_class == "RuntimeError"`.
2. **clean shutdown + `stop()` raises** — no exception in flight. Assert `result.exit_code != 0` (the failure stays visible — it is the only signal) **and** the loud row is present. This is the test that distinguishes "cleanup can no longer mask" from "cleanup silently swallowed a real problem"; the chosen behaviour (propagate on clean shutdown) must be pinned here and stated in the PR body.
3. **clean shutdown + `stop()` succeeds** — the non-raising arm. Assert `result.exit_code == 0`, no `supervisor_stop_failed` row, pidfile gone.

Read `test_daemon_boot_reap_finally.py`'s existing `test_reap_finally_skips_absent_supervisor_and_pidfile` and reuse its harness/env. Drive `stop()` raising via the supervisor fixture (`tests/unit/cli/daemon/conftest.py`).

- [ ] **Step 2: Run and verify FAILS** — arm 1 currently propagates `RuntimeError` (wrong exit code); arms 2/3 fail on the missing log row / behaviour.

- [ ] **Step 3: Apply the fix**

Add the sentinel on the outer boot `try` (the one whose `finally` begins at `:990`):

```python
    boot_failure: BaseException | None = None
    try:
        ...  # existing boot body through ``await wait_for_shutdown(supervisor)``
    except BaseException as exc:
        boot_failure = exc
        raise
    finally:
        ...  # existing going_down + reap chain
```

Then, at `:1027-1028`, replace the bare call:

```python
                if supervisor is not None:
                    # Cleanup that runs while a real failure may already be in flight —
                    # a ``_BootRefusedError`` the daemon has ALREADY audited. Letting
                    # ``stop()`` raise here would REPLACE it, so the operator gets the wrong
                    # reason/exit code for the failure that actually happened (#472 finding 3).
                    # But on a CLEAN shutdown ``stop()`` raising is the ONLY signal (a
                    # persistence failure re-raised by core err-002, or an unwritable
                    # shutdown audit) — so suppress ONLY while unwinding a real failure, and
                    # re-raise otherwise. ``except Exception`` not ``BaseException``:
                    # core.stop() deliberately re-raises SystemExit/KeyboardInterrupt so an
                    # operator Ctrl-C on a hung shutdown is honoured. The failure is never
                    # hidden — it is logged with its error class right here (HARD #7).
                    try:
                        await supervisor.stop()
                    except Exception as exc:
                        log.error(
                            "daemon.shutdown.supervisor_stop_failed",
                            error_class=type(exc).__name__,
                        )
                        if boot_failure is None:
                            raise
```

Keep the H1 ORDERING INVARIANT comment (`:1020-1026`) above this block. The three sibling `with suppress(Exception)` cleanups at `:1031/:1040/:1047` are **deliberately not** given this shape — their defect is *silence* (no `error_class`), not *masking*, which is a different fix. State that in the PR body so the asymmetry reads as a decision (raise it as a follow-up; do not fold it in).

- [ ] **Step 4: Run and verify PASS** (all three arms).

- [ ] **Step 5: Mutation-check + coverage**

Revert the `if boot_failure is None: raise` → arm 2 must fail (clean-shutdown failure goes silent). Revert the whole try/except → arm 1 must fail. Re-apply.

```bash
uv run pytest tests/unit --cov=alfred.cli.daemon._commands --cov-report=term-missing --cov-branch -q
```

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_daemon_boot_reap_finally.py
git commit -m "fix(cli): #472 stop supervisor.stop() masking a boot refusal without silencing clean-shutdown failures"
```

---

### Task A4: ADR note + PR-A gates + PR

- [ ] **Step 1: ADR-0052 dated note.** Add a short dated line under the budget-ceiling paragraph (`:280-287`) recording that the retry back-off was the one budget term not clamped to the absolute deadline (≤1.0s overrun, nesting invariant never actually breached), now fixed in #472. One owner, one edit — do not let batches amend it blind.

- [ ] **Step 2: Full gates.**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/
uv run pytest tests/adversarial -q          # release-blocking: security touched
uv run pytest tests/unit -q && uv run pytest tests/integration -q
uv run pytest tests/unit \
  --cov=alfred.security.quarantine_child.provider_dispatch \
  --cov=alfred.security.quarantine_child.brokered_egress \
  --cov=alfred.cli.daemon._commands \
  --cov-report=term-missing --cov-branch -q
make check; echo "EXIT=$?"   # last; never pipe through tail
```

macOS integration flake under load is known — verify suspects in isolation, trust Linux CI.

- [ ] **Step 3: Open PR-A.** Body states: the three findings and where fixed; that finding 4 is fixed in `bind()` → `ProviderUnavailableError` (rejecting both the issue's `provider_dispatch` catch and a `TimeoutError` mapping, with the err-002 rationale); the corrected false comment at `provider_dispatch.py:207-214`; the loud-log addition closing a pre-existing gap on the `ProviderUnavailableError` arm; the ≤1.0s / no-actual-breach severity calibration for finding 1; the clean-shutdown-stays-visible decision for finding 3; and the deferred three-sibling `suppress` silence as a separate follow-up.

- [ ] **Step 4: Review.** Full `/review-pr` fleet (security always) + UAT, then CodeRabbit — run **both** channels and parse the review **BODY** as well as `reviewThreads` (the #475 gap that let these findings merge). Resolve every thread; `gh pr merge --rebase`. Never `--admin`.

---

## PR-B — finding 2, cancellation-safe revoke (Major)

Branch: `472b-cancellation-safe-revoke` off `main` (after PR-A merges, or in parallel — no file overlap).

**Why the naive fix is wrong.** `except asyncio.CancelledError: <swallow>` breaks structured concurrency (the supervisor's `await self._run_task` at `core.py:609` never sees the task end cancelled; an enclosing `TaskGroup.__aexit__` waits on us; an outer `asyncio.timeout` never `uncancel`s, poisoning enclosing scopes). The fix must **complete the kill and still propagate the cancel**.

**Why the kill must be synchronous.** A single `task.cancel()` delivers one `CancelledError`, so awaits in the handler *would* work — but two `TaskGroup` siblings failing deliver two cancels (verified: `_on_task_done` calls `_abort()` per errored child), and a re-delivered cancel makes every `await` re-raise immediately. A trust-boundary invariant must not rest on the delivery count. `Popen.kill()` cannot be pre-empted.

**Why SIGKILL alone is a complete revocation.** The launcher `exec`s bwrap (`bin/alfred-plugin-launcher.sh:528`), so under `--unshare-pid` `self._process` **is** bwrap = PID 1 of the child PID namespace; SIGKILL tears down the whole namespace. It is the same PID `_terminate_and_reap` signals. A SIGKILLed process's fd table is torn down instantly → every brokered gateway socket revoked. Residual: a `send()` already in the kernel on an established socket can complete — a microsecond window vs "alive indefinitely".

### Task B1: `_SubprocessChildIO.abort()`

**Files:** `src/alfred/security/quarantine_child_io.py` (new method beside `aclose`, `:757-784`); `tests/unit/security/test_quarantine_child_io.py`

- [ ] **Step 1: Write failing tests B, B2** (both `@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")` decorators)

Test B — `abort()` kills, oracle = the kernel:

```python
def test_abort_sigkills_the_child() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _SubprocessChildIO(proc).abort()
        proc.wait(timeout=5)
        assert proc.returncode == -signal.SIGKILL
    finally:
        proc.kill()  # no-op if already dead; prevents a leaked sleeper on assert failure
```

Test B2 — the `control_parent is not None` branch (required for 100% branch; both B and C construct with `control_parent=None`). Mirror the real-socketpair harness at `tests/unit/security/test_quarantine_child_io_broker.py:349`:

```python
def test_abort_closes_the_control_parent_end() -> None:
    parent, _child = socket.socketpair()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], ...)
    try:
        _SubprocessChildIO(proc, control_parent=parent).abort()
        assert parent.fileno() == -1, "control end survived abort() — capability not revoked"
    finally:
        proc.kill(); proc.wait(timeout=5)
```

Oracle is the kernel fd (`fileno() == -1`), independent of any internal flag.

- [ ] **Step 2: Run, verify FAIL** (`AttributeError: abort`).

- [ ] **Step 3: Implement `abort()`**

```python
    def abort(self) -> None:
        """SIGKILL the child + close the control end. SYNCHRONOUS: never awaits, never raises.

        The cancellation-safe half of :meth:`aclose`. ``aclose`` is the graceful teardown
        (SIGTERM -> SIGKILL -> reap -> stderr drain -> fd close) and EVERY stage awaits, so a
        cancel mid-teardown aborts it partway. This revokes the capability with the one
        operation the kernel guarantees and that cannot be caught, blocked or ignored.

        Under the shipped kind="full" policy the launcher ``exec``s bwrap
        (``bin/alfred-plugin-launcher.sh:528``) with ``--unshare-pid``, so ``self._process``
        IS bwrap — PID 1 of the child PID namespace — and SIGKILLing it tears down the whole
        namespace, python child included. Same PID ``_terminate_and_reap`` already signals.

        Does NOT reap. ``aclose`` sets ``_closed`` BEFORE tearing down and every caller of
        this method is reached after ``aclose`` was entered, so a later ``aclose`` early-
        returns without reaping. Usually harmless: the SIGKILL releases the ``waitpid`` that
        ``_reap_within`` left an executor thread parked on, and that thread reaps the child.
        In the narrow case where no such thread is parked (cancel landed before submission,
        or after ``_reap_within`` already gave up), a zombie survives — it holds no fds, no
        memory and no capability, only a process-table entry the OS reaps at daemon exit.

        Residual, accepted: a ``send()`` already queued in the kernel on an established
        socket can still complete — a microsecond window against "alive indefinitely".
        """
        with contextlib.suppress(ProcessLookupError, OSError):
            self._process.kill()
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()
```

- [ ] **Step 4: Run, verify PASS; mutation-check** (drop `self._process.kill()` → B fails; drop the control-parent close → B2 fails).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io.py
git commit -m "feat(security): #472 add synchronous _SubprocessChildIO.abort() for cancel-safe revoke"
```

### Task B2: Widen `ChildIO` Protocol + all doubles + structural guard

**Files:** `quarantine_transport.py:184-190`; the 7+ doubles below; `tests/unit/security/test_quarantine_child_io.py:482` (the sole runtime `issubclass` site)

- [ ] **Step 1: Add `def abort(self) -> None: ...`** after `aclose` in the Protocol.

- [ ] **Step 2: Add `abort()` stubs to every double.** Verified complete list — mypy/pyright/`issubclass` will NOT flag a miss (Global Constraints), so this must be exhaustive:
  - `_RecordingChildIO` (`test_quarantine_transport.py:61`) — covers its subclasses `:117/:227/:242/:428/:987` and grandchildren `:257/:264` by inheritance
  - `_OrderRecordingChildIO` (`test_quarantine_transport.py:155`) — standalone, NOT a subclass
  - `_ChildIO` (`test_quarantine_revocation_metric.py:103`) and `_ExplodingChildIO` (`:131`)
  - `_AcloseOnlyChildIO` (`test_broker_audit_wiring.py:156`), `_FakeBrokeringChildIO` (`:268`)
  - `_FakeQuarantineChildIO` (`tests/unit/cli/daemon/conftest.py:398`)
  - `_MaliciousChild` (`tests/adversarial/tier_laundering/test_tier_laundering_quarantine_ingest_extract.py:72`)
  Integration sites use the real `_SubprocessChildIO` — no change. Re-grep `class _.*ChildIO` and any `ChildIO` Protocol claim before finalising.

- [ ] **Step 3: Add a structural guard** so the list cannot silently rot. Parametrise over every double:

```python
@pytest.mark.parametrize("double", [_RecordingChildIO, _RaisingChildIO, _CloseRaisingChildIO,
    _HangingCloseChildIO, _StallingChildIO, _OrderRecordingChildIO, _ContentHandleReturningChildIO])
def test_every_childio_double_satisfies_the_protocol(double: type) -> None:
    assert issubclass(double, ChildIO)
```

(and the equivalents in the other test files, or a shared helper). `issubclass` on a `runtime_checkable` Protocol checks method presence — this is the gate mypy/pyright do not provide for tests.

- [ ] **Step 4: `mypy --strict src` + `pyright src` + full transport/metric/broker-wiring suites green.** Commit.

### Task B3: The handler arms

**Files:** `quarantine_transport.py:605-622` + new `_abort_child_now`; `tests/unit/security/test_quarantine_transport.py`

- [ ] **Step 1: Write failing tests A, C, D**

Test A — transport completes the kill on cancel (cross-platform, spy oracle; both halves load-bearing):

```python
class _CancelDuringCloseChildIO(_RecordingChildIO):
    def __init__(self) -> None:
        super().__init__(); self.in_aclose = asyncio.Event(); self.aborted = False
    async def aclose(self) -> None:
        self.in_aclose.set(); await asyncio.sleep(3600)
    def abort(self) -> None:
        self.aborted = True

@pytest.mark.asyncio
async def test_cancel_mid_teardown_kills_child_and_propagates() -> None:
    child = _CancelDuringCloseChildIO()
    transport = _staged_transport(child, auditor=_RecordingAuditor())
    with structlog.testing.capture_logs() as logs:
        task = asyncio.create_task(transport._revoke_child_capability())
        await child.in_aclose.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert child.aborted
    assert not [e for e in logs if e["event"] == "security.quarantine_transport.capability_abort_failed"], \
        "abort() was missing/broken on the double — this test proved nothing"
```

Test C — the finding end to end, mutation-proofed, deterministic barrier (no `sleep(0.05)` race):

```python
class _BarrierSubprocessChildIO(_SubprocessChildIO):
    def __init__(self, proc): super().__init__(proc); self.entered = asyncio.Event()
    async def aclose(self) -> None:
        self.entered.set(); await super().aclose()   # real SIGTERM / real reap

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.asyncio
async def test_cancel_mid_real_teardown_sigkills_the_child(monkeypatch) -> None:
    monkeypatch.setattr(child_io_mod, "_REAP_SIGTERM_GRACE_S", 30.0)  # SIGKILL escalation CANNOT run
    proc = subprocess.Popen([sys.executable, "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('up', flush=True); time.sleep(300)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.stdout.readline()  # barrier: SIGTERM handler installed
        child = _BarrierSubprocessChildIO(proc)
        transport = _staged_transport(child, auditor=_RecordingAuditor())
        task = asyncio.create_task(transport._revoke_child_capability())
        await child.entered.wait()  # deterministic — same shape as test A
        task.cancel()
        with pytest.raises(asyncio.CancelledError):  # disambiguates the arm; load-bearing
            await task
        proc.wait(timeout=5)
        assert proc.returncode == -signal.SIGKILL
    finally:
        proc.kill(); proc.wait(timeout=5)
```

`SIG_IGN` + `_REAP_SIGTERM_GRACE_S=30.0` together prove `abort()` is the *only* thing that could have killed it (a plain sleeper dies to the SIGTERM `_terminate_and_reap` sends; the built-in escalation can't run in the cancel window). Do not drop either. A comment: two threads call `proc.wait()` (test + parked executor) — safe, CPython serialises on `_waitpid_lock`; the executor thread outlives the test.

Test D — the abort-raises branch (100% branch): a double whose `abort()` raises `OSError`. Assert `capability_abort_failed` in `capture_logs()` **and** `CancelledError` still propagates.

- [ ] **Step 2: Run, verify all FAIL.**

- [ ] **Step 3: Implement the arms** (abort BEFORE log; both emits suppressed; TRAP comment as mechanism, not absolute)

```python
        # The ``async with asyncio.timeout`` MUST stay INSIDE this ``try``. asyncio.timeout
        # implements its bound by cancelling the inner task; ``Timeout.__aexit__`` converts
        # that CancelledError to TimeoutError ONLY when the timeout expired AND
        # ``task.uncancel()`` returns to the count snapshotted at ``__aenter__``. So:
        # bound-expiry alone -> TimeoutError arm; an EXTERNAL cancel also outstanding ->
        # no conversion, the CancelledError arm fires and re-raises (correct: a real cancel
        # is pending). ``__aenter__`` snapshots ``cancelling()`` as a baseline, which is why
        # the bound still converts correctly when this method is re-entered from inside an
        # already-cancelled scope (``_run_broker_preamble``'s ``except BaseException``).
        # Inverting (try inside the async with) would put __aexit__ outside every arm and
        # make ``revoke_deadline_exceeded`` unreachable.
        try:
            async with asyncio.timeout(_REVOKE_TIMEOUT_S):
                await self._child_io.aclose()
        except TimeoutError:
            # BOUNDED because the caller still has an audit row to write. The 5s bound cut
            # ``aclose`` short and today nothing then kills the child — so finish the kill
            # synchronously (#472: same hole as the cancel arm, different trigger). Kill
            # BEFORE logging: the invariant is the kill, not the line.
            self._abort_child_now()
            with contextlib.suppress(Exception):
                _log.error(
                    "security.quarantine_transport.revoke_deadline_exceeded",
                    timeout_s=_REVOKE_TIMEOUT_S,
                )
        except asyncio.CancelledError:
            # A cancel MID-teardown (daemon-stop force-cancel, a TaskGroup sibling failure,
            # an outer action_deadline) would otherwise abort the revoke and leave a T3 child
            # ALIVE holding brokered gateway sockets — the state this method prevents.
            # ``except Exception`` below does NOT catch this (CancelledError is BaseException
            # since 3.8). Complete the kill SYNCHRONOUSLY so the invariant does not depend on
            # the cancellation-delivery count, THEN re-raise (swallowing breaks structured
            # concurrency). Kill first, log suppressed — an emit failure must not preempt
            # either the kill or the re-raise.
            self._abort_child_now()
            with contextlib.suppress(Exception):
                _log.error("security.quarantine_transport.revoke_cancelled")
            raise
        except Exception as exc:
            # No abort: ``aclose`` runs ``_terminate_and_reap`` FIRST and that never raises,
            # so any exception escaping ``aclose`` is from a LATER stage — the reap already ran.
            with contextlib.suppress(Exception):
                _log.error(
                    "security.quarantine_transport.capability_revoke_failed",
                    error_class=type(exc).__name__,
                )

    def _abort_child_now(self) -> None:
        """Synchronous last-resort kill. Never awaits, never raises, never preempts a re-raise.

        ``ChildIO.abort`` is contracted never to raise, but this runs inside a
        ``CancelledError`` handler on a trust-boundary path: an ``AttributeError`` from a
        malformed seam would REPLACE the CancelledError and silently break cancellation
        propagation. Guarded + loud (HARD #7). The negative-log assertions in the arm tests
        ensure a double that is MISSING ``abort`` cannot pass here silently.
        """
        try:
            self._child_io.abort()
        except Exception as exc:
            with contextlib.suppress(Exception):
                _log.error(
                    "security.quarantine_transport.capability_abort_failed",
                    error_class=type(exc).__name__,
                )
```

`CAPABILITY_REVOKED_COUNTER.inc()` at `:604` stays before the `try`.

- [ ] **Step 4: Run, verify PASS.**

- [ ] **Step 5: Regression — the timeout arm did NOT break**

```bash
uv run pytest tests/unit/security/test_quarantine_transport.py -q -k "hanging or deadline"
uv run pytest tests/unit/security/test_quarantine_revocation_metric.py -q
```

`test_hanging_revoke_is_logged_loudly` / `test_hanging_revoke_still_writes_the_refusal_row` must pass. **Also** add `child.aborted` to whichever of these drives the timeout arm (arch H4 — the arm now aborts and today no test observes that). If either fails on `revoke_deadline_exceeded` reachability, the TRAP was sprung — check `async with` is inside the `try`.

- [ ] **Step 6: Mutation-check A and C**, commit.

### Task B4: Outer-scope + residual + idempotency tests

- [ ] **Outer-scope (`_refuse_broker` at `:568`, 11s bound over the 5s inner).** Add to the timeout-arm test: `assert not [e for e in logs if e["event"] == "security.quarantine_transport.revoke_cancelled"]` — proves the inner 5s bound wins and the outer 11s refusal timeout is not misattributed as a cancel. Add one test where the outer bound *does* fire first (child then hard-killed via the cancel arm) and state it as accepted behaviour in the PR body.
- [ ] **Zombie residual pinning** (the docstring's load-bearing claim): after a cancel+abort on a real `_SubprocessChildIO`, `await io.aclose()` again and assert it early-returns without re-reaping (e.g. `_closed is True` was already set; `proc` already dead). Cheap, locks the accepted residual as behaviour not prose.
- [ ] **`abort()` idempotency:** call `abort()` twice, and once on an already-reaped child — assert neither raises (the "never raises" contract).
- [ ] **Counter on the cancelled path:** assert `CAPABILITY_REVOKED_COUNTER` incremented on the cancel arm (the counter is at `:604`, before the `try`; a cancelled teardown is a new arm through it). Note `b2685acd` already de-vacuumed this metric's registration assertion — do not reintroduce a vacuous one.

### Task B5: Adversarial coverage

- [ ] Add a capability-bypass corpus case: "a cancel storm during revoke must not leave a T3 child alive holding brokered gateway sockets." Use the `alfred-adversarial-corpus` skill for naming/layout. If a unit-level proof is judged sufficient, state *why* in the PR body — do not leave a `src/alfred/security/` capability property unaddressed in `tests/adversarial`.

### Task B6: Docs (one owner, at the end — do not let tasks amend blind)

- [ ] **`_revoke_child_capability` docstring** (`quarantine_transport.py:576-598`): it currently says a failing teardown is "logged LOUD ... and swallowed ... must not preempt the caller's graceful typed refusal." The new arm **re-raises** on cancel. Amend to distinguish *failed* teardown (swallowed, typed refusal survives) from *cancelled* teardown (kill completed, cancel propagates, no typed refusal — structured concurrency outranks the graceful exit).
- [ ] **ADR-0052 dated amendment:** the revoke-cancel behaviour change; the two new structlog events; the accepted residuals (narrow-case zombie; in-flight `send()` window). Do not restate PR-A's backoff note as a separate assertion.
- [ ] **`docs/subsystems/security.md`** (revocation paragraph, ~`:443-455`): add `revoke_cancelled` and `capability_abort_failed` to the operator signal list.
- [ ] **`docs/runbooks/quarantine-capability-revoked.md`**: new events + what a lingering bwrap zombie PID means during triage.
- [ ] **`docs/subsystems/quarantine.md:248`** (child stderr on `aclose` is logged-not-persisted): one clause noting `abort()` skips the stderr drain entirely.
- [ ] Run `markdownlint-cli2@0.22.1 "docs/**/*.md"` (no `| tail`) and the docs link/anchor checker.

### Task B7: PR-B gates + PR

- [ ] Full gates as PR-A Task A4 Step 2, plus the transport/child-io/revocation-metric per-module 100% gates:

```bash
uv run pytest tests/unit --cov=alfred.security.quarantine_transport \
  --cov=alfred.security.quarantine_child_io --cov-report=term-missing --cov-branch -q
```

- [ ] Open PR-B. Body states: the cancellation-safety argument (delivery-count → synchronous kill); the TRAP mechanism (case (c) reaches the arm — not an absolute); the `ProviderUnavailableError`-style laddering N/A here; the accepted residuals; that no gateway twin exists (`GatewayAdapterStdioTransport` is not a `ChildIO` implementer — one line so a reviewer needn't ask); the folded-in `TimeoutError`-arm abort (same responsibility) and its test; and that `close()` (`:625-627`) is left untouched because the daemon `finally` reaps separately (state why, don't leave the sibling unmentioned).
- [ ] Review: full `/review-pr` fleet (security always) + UAT, both CodeRabbit channels incl. the review BODY, resolve every thread, `gh pr merge --rebase`.

---

## Self-Review

**Spec coverage:** finding 1 → A1; finding 4 → A2; finding 3 → A3; finding 2 → B1-B7. Acceptance: TDD-with-demonstrated-failure → every task's Steps 1-2 + an explicit mutation-check; `src/alfred/security/` 100% → each PR's coverage step; adversarial green → each PR's gates + B5; finding-1 behavioural bound → A1's spy oracle asserts elapsed-at-call-site, not that a `min()` was applied.

**Placeholders:** none. Where a test must match an existing harness the plan names the file to read and reuse (`_FakeSource`, `_staged_transport`/`_RecordingAuditor`, the `CliRunner` daemon harness, the real-socketpair child-io harness). Assertion shapes given in full.

**Type consistency:** `abort()` is `def abort(self) -> None` in the Protocol, `_SubprocessChildIO`, all 8 doubles, and `_abort_child_now`'s call. `_abort_child_now` defined and used only in Task B3.

**Deviations from the source issue, all flagged for reviewers:** finding 4 → `ProviderUnavailableError` in `bind()` (not the issue's `provider_dispatch` catch, not `TimeoutError`); finding 3 → conditional re-raise (not a bare `suppress`); split into two PRs.
