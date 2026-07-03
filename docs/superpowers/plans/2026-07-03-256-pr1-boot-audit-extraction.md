# #256 PR-1 — Extract `_boot_audit.py` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the daemon's audited-refusal + lifecycle-emit cluster out of the 2789-line `src/alfred/cli/daemon/_commands.py` into a new leaf module `src/alfred/cli/daemon/_boot_audit.py`, and gate it at per-file 100% line+branch coverage — the first (lowest-risk, dependency-leaf) extraction of the `#256` split.

**Architecture:** Pure symbol move, zero behaviour change. `_boot_audit.py` becomes the dependency leaf (`_failures.py ← _boot_audit.py`); `_commands.py` re-imports the 7 symbols its still-resident `_start_async` + comms helpers + `start_daemon` call, so every existing `monkeypatch.setattr("...._commands.X")` seam and cross-module import keeps working unchanged. The cluster is **already at 100% coverage** by the daemon unit suite (measured), so the per-file gate needs no new production-covering tests.

**Tech Stack:** Python 3.12+, asyncio, pytest + pytest-cov (branch), coverage.py, mypy `--strict` + pyright, ruff, Babel (pybabel) for i18n catalogs, GitHub Actions (per-file `coverage report --fail-under=100` gate steps).

## Global Constraints

- **Security-critical fail-closed code.** This cluster is the audited boot-refusal mechanism. No behaviour change: the boot sequence, refusal reasons, audit-row shapes, exit-code contract (2 = refused, 3 = audit-unwritable), and CLI stdout/stderr stay byte-identical. A default-empty boot stays byte-for-byte unchanged.
- **Branch off `main`; work on `refactor/256-daemon-boot-split` (already created, at commit `92482030`). Never commit to `main`.**
- **Design source of truth:** `docs/superpowers/specs/2026-07-03-daemon-commands-boot-refactor-design.md`.
- **Anti-pragma rule:** `# pragma: no cover` is permitted ONLY on genuinely-unreachable real-infra constructors. `_boot_audit.py` contains none — it must reach 100% with zero pragma lines. A pragma on any refusal/emit/decision line is forbidden.
- **`make check` before every push** (lint + format + type + unit). After this PR: full `tests/unit` + release-blocking `tests/adversarial` green + a real `/review-pr` pass (security always) + CodeRabbit.
- **i18n:** 3 `t()` call sites move — regenerate the catalog and commit `locale/en/LC_MESSAGES/alfred.po`; never `--omit-header`.
- **No `--no-verify`. No `--admin` merge.**

## Symbol move inventory (exact source line ranges in `_commands.py` @ `92482030`)

Move these 12 symbols (verbatim) from `_commands.py` into `_boot_audit.py`, in this order:

| Symbol | Current lines | Notes |
| ------ | ------------- | ----- |
| `_EXIT_REFUSED` | 150–151 | Exit-code constant + its comment. Referenced only at old 1963 (moves). |
| `_EXIT_AUDIT_UNWRITABLE` | 152 | Referenced only at old 1847 (moves). |
| `_BootRefusedError` | 169–178 | Control-flow signal caught by `start_daemon` (re-imported into `_commands`). |
| `_LIFECYCLE_WIRE_SEND_EXCEPTIONS` | 504–509 | Tuple; needs `CommsProtocolError`. |
| `_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS` | 511–517 | Comment 511–516 + the `= 2.0` line 517. |
| `LifecycleBroadcaster` | 587–661 | Uses `log`, `asyncio`, the two lifecycle constants, the protocol constants. |
| `_emit_or_quarantine` | 1812–1847 | Contains `t("daemon.boot.audit_log_unwritable")` (1846). |
| `_emit_ready` | 1850–1888 | Contains `t("daemon.lifecycle.ready", ...)` (1888). |
| `_emit_going_down` | 1891–1927 | Contains `t("daemon.lifecycle.going_down", ...)` (1927). |
| `_refuse_boot` | 1930–1963 | `NoReturn`; calls `_invoke_boot_failed` + `_emit_or_quarantine`. |
| `_invoke_boot_failed` | 1966–1992 | Internal to `_refuse_boot`. **No test refs → NOT re-imported into `_commands`.** |
| `_invoke_boot_completed` | 1995–2019 | Called by `_start_async` (re-imported). |

**Do NOT move** (they stay in `_commands.py`): `_STATE_GIT_HEAD_UNKNOWN` (154–155), `_STUB_OPERATOR_ID` (157–159), `_StubOperatorResolver` (162–166), `_DURABLE_INTAKE_ACK_INTERVAL_SECONDS` / `_ACK_NOT_YET_EMITTED` (519–534, comms), `log` (keep the existing one in `_commands`; `_boot_audit` gets its own).

## `_boot_audit.py` import block (exact — top of the new file)

```python
"""Daemon boot audit + lifecycle-emit — the audited refusal mechanism (#256 PR-1).

Extracted from ``_commands.py`` (the dependency leaf of the boot module split):
the ``daemon.boot.failed`` refusal path (``_refuse_boot`` — invoke hookpoint,
emit the failed row, exit 2), the audit-append-or-quarantine primitive
(``_emit_or_quarantine`` — a failed audit write is loud, exit 3; sec-003), the
``daemon.lifecycle.ready`` / ``going_down`` emits, and the boot-local
``LifecycleBroadcaster`` fan-out of lifecycle wire frames to the socket carrier.

Fail-closed: every ``append_schema`` on a refusal/completion path quarantines
with exit 3 on an audit-write failure; ``_refuse_boot`` is ``NoReturn`` so no
refusal can fall through into ``Supervisor`` construction.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NoReturn

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    DAEMON_BOOT_FAILED_FIELDS,
    DAEMON_LIFECYCLE_FIELDS,
)
from alfred.cli.daemon._failures import DaemonBootFailure
from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LIFECYCLE_REASON_SHUTDOWN,
)
from alfred.i18n import t
from alfred.plugins.comms_wire import CommsProtocolError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from alfred.audit.log import AuditWriter

log = structlog.get_logger(__name__)
```

(Then paste the moved symbols in the inventory order. `_invoke_boot_failed` / `_invoke_boot_completed` keep their function-local `from alfred.hooks…` imports verbatim.)

## `_commands.py` re-import block (exact — add to the daemon-package import group)

```python
from alfred.cli.daemon._boot_audit import (
    LifecycleBroadcaster,
    _BootRefusedError,
    _emit_going_down,
    _emit_or_quarantine,
    _emit_ready,
    _invoke_boot_completed,
    _refuse_boot,
)
```

(Run `ruff check --fix` to canonicalise import ordering — do not hand-tune it. All 7 names are used in `_commands.py` — `_refuse_boot` / `_emit_or_quarantine` by `_start_async` and the still-resident comms helpers, `_emit_ready` / `_emit_going_down` / `_invoke_boot_completed` by `_start_async`, `LifecycleBroadcaster` by `_start_async` + `test_lifecycle_wire_send.py`, `_BootRefusedError` by `start_daemon` — so none are F401. `_invoke_boot_failed` and the two `_EXIT_*` constants are NOT re-imported: after the move nothing in `_commands.py` references them.)

---

### Task 1: Move the cluster into `_boot_audit.py` (two-commit reviewable move)

Per the spec's `devex-001` reviewability rule, the move is two commits: (1) a pure cut/paste (verifiable as zero content change via `--color-moved`), (2) the re-import fixup that makes the tree green. Commit 1 intentionally leaves `_commands.py` unimportable; commit 2 restores it. The branch tip is green.

**Files:**

- Create: `src/alfred/cli/daemon/_boot_audit.py`
- Modify: `src/alfred/cli/daemon/_commands.py` (delete the 12 symbols; add the re-import)
- Test (safety net, unchanged): `tests/unit/cli/daemon/test_daemon_boot_completed_emit.py`, `test_daemon_boot_failure_union.py`, `test_daemon_lifecycle_signal.py`, `test_lifecycle_wire_send.py`, `test_daemon_start_probe_refusals.py`

**Interfaces:**

- Produces (imported by `_commands.py` and, unchanged, by tests): `LifecycleBroadcaster`, `_BootRefusedError(code: int)` with `.code: int`, `async _refuse_boot(audit, failure, message, *, boot_id, environment_source) -> NoReturn`, `async _emit_or_quarantine(audit, *, fields, schema_name, event, subject, result) -> None`, `async _emit_ready(audit, *, boot_id, epoch, broadcaster) -> None`, `async _emit_going_down(audit, *, boot_id, epoch, broadcaster) -> None`, `async _invoke_boot_completed(boot_id, state_git_head_sha) -> None`. Module-private: `_invoke_boot_failed`, `_EXIT_REFUSED=2`, `_EXIT_AUDIT_UNWRITABLE=3`, `_LIFECYCLE_*`.

- [ ] **Step 1: Create `_boot_audit.py` with the import block + pasted symbols**

Create `src/alfred/cli/daemon/_boot_audit.py` with the exact import block above, then paste the 12 symbols verbatim from `_commands.py` in the inventory order (`_EXIT_*`, `_BootRefusedError`, `_LIFECYCLE_*`, `LifecycleBroadcaster`, `_emit_or_quarantine`, `_emit_ready`, `_emit_going_down`, `_refuse_boot`, `_invoke_boot_failed`, `_invoke_boot_completed`). Do not edit the bodies.

- [ ] **Step 2: Delete the moved symbols from `_commands.py`**

Remove the same 12 symbols (source lines per the inventory table) from `_commands.py`. Do NOT add the re-import yet (this keeps commit 1 a pure move). Also remove any now-unused imports this exposes in `_commands.py` **only if** `ruff check` flags them in Step 5 — defer that to Step 5, do not guess here.

- [ ] **Step 3: Verify the move is content-neutral**

Run: `git add -A && git diff --cached --color-moved=zebra --stat`
Expected: `_boot_audit.py` added ≈ lines removed from `_commands.py` for the moved blocks; `--color-moved=zebra` renders the moved bodies as moved (not add/delete). Eyeball that no body line changed.

- [ ] **Step 4: Commit the pure move**

```bash
git commit -m "refactor(daemon): move boot-audit cluster to _boot_audit.py (pure move) (#256)"
```

- [ ] **Step 5: Add the re-import to `_commands.py` + fix imports**

Add the 7-symbol re-import block (above) to `_commands.py`. Then:
Run: `uv run ruff check --fix src/alfred/cli/daemon/ && uv run ruff format src/alfred/cli/daemon/`
Expected: clean; ruff removes any import in `_commands.py` left unused by the move (e.g. an audit-schema symbol only the moved code used) and sorts the new re-import. If ruff removes a symbol the moved code still needs, it is now in `_boot_audit.py`'s own import block — confirm `_boot_audit.py` imports it.

- [ ] **Step 6: Type-check both modules**

Run: `uv run mypy src/alfred/cli/daemon/_boot_audit.py src/alfred/cli/daemon/_commands.py && uv run pyright src/alfred/cli/daemon/_boot_audit.py`
Expected: no errors. (`_boot_audit` must import cleanly with no cycle — it never imports `_commands`.)

- [ ] **Step 7: Run the daemon unit suite (the behaviour-preservation safety net)**

Run: `uv run pytest tests/unit/cli/daemon -q -p no:cacheprovider`
Expected: `270 passed` (same as base). No seam repoints were needed (no test patches the moved refusal/emit symbols; `LifecycleBroadcaster` is re-exported with identical class identity), so every test passes unchanged.

- [ ] **Step 8: Commit the fixup**

```bash
git add -A
git commit -m "refactor(daemon): re-import _boot_audit seams into _commands (#256)"
```

---

### Task 2: Regenerate the i18n catalog (3 moved `t()` sites)

**Files:**

- Modify: `locale/en/LC_MESSAGES/alfred.po` (and `alfred.mo` if tracked)

**Interfaces:**

- Consumes: the moved `t("daemon.boot.audit_log_unwritable")`, `t("daemon.lifecycle.ready")`, `t("daemon.lifecycle.going_down")` call sites now in `_boot_audit.py`.

- [ ] **Step 1: Confirm the catalog is currently stale (proves the regen is needed)**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && uv run pybabel update --check -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --ignore-pot-creation-date; echo "exit=$?"`
Expected: `exit=1` (drift — the `#:` location refs for the 3 moved msgids now point at `_boot_audit.py`). This is exactly the CI gate at `.github/workflows/pr-validate-python.yml:381`.

- [ ] **Step 2: Regenerate + compile the catalog**

Run: `uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching && uv run pybabel compile -d locale -D alfred --statistics`
Expected: update succeeds; the 3 msgids are unchanged (no new/obsolete strings — the diff is only `#:` location lines moving from `_commands.py` to `_boot_audit.py`). No `--omit-header`.

- [ ] **Step 3: Confirm the catalog is now clean**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && uv run pybabel update --check -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --ignore-pot-creation-date; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 4: Commit the catalog**

```bash
git add locale/en/LC_MESSAGES/alfred.po
git status --porcelain locale/  # if alfred.mo shows as modified and is tracked, add it too
git add locale/en/LC_MESSAGES/alfred.mo 2>/dev/null || true
git commit -m "i18n(daemon): re-home boot-audit t() location refs to _boot_audit (#256)"
```

---

### Task 3: Add the per-file 100% coverage gate (both CI jobs) + single-definition guard test

**Files:**

- Modify: `.github/workflows/ci.yml` (unit-coverage job near line 267; combined `coverage-gates` job near line 1583)
- Create: `tests/unit/cli/daemon/test_boot_audit_module.py`

**Interfaces:**

- Consumes: `alfred.cli.daemon._boot_audit` (the extracted module) and `alfred.cli.daemon._commands` (the re-import).

- [ ] **Step 1: Write the single-definition + exit-code identity test**

Create `tests/unit/cli/daemon/test_boot_audit_module.py`:

```python
"""Guard the _boot_audit extraction seam: single _BootRefusedError definition
re-imported into _commands, and the exit-code contract (#256 PR-1)."""

from alfred.cli.daemon import _boot_audit, _commands


def test_boot_refused_error_is_single_definition() -> None:
    # start_daemon (in _commands) catches _BootRefusedError by identity; a second
    # definition would silently stop catching a refusal raised in _boot_audit.
    assert _commands._BootRefusedError is _boot_audit._BootRefusedError


def test_exit_code_contract_unchanged() -> None:
    assert _boot_audit._EXIT_REFUSED == 2
    assert _boot_audit._EXIT_AUDIT_UNWRITABLE == 3
    assert _boot_audit._BootRefusedError(_boot_audit._EXIT_REFUSED).code == 2
    assert _boot_audit._BootRefusedError(_boot_audit._EXIT_AUDIT_UNWRITABLE).code == 3


def test_start_daemon_maps_refusal_to_typer_exit(monkeypatch) -> None:
    import typer

    async def _refuse() -> None:
        raise _boot_audit._BootRefusedError(_boot_audit._EXIT_REFUSED)

    monkeypatch.setattr(_commands, "_start_async", _refuse)
    try:
        _commands.start_daemon()
    except typer.Exit as exit_:
        assert exit_.exit_code == 2
    else:
        raise AssertionError("start_daemon did not raise typer.Exit on refusal")
```

- [ ] **Step 2: Run it — expect PASS (behaviour already present, this pins it)**

Run: `uv run pytest tests/unit/cli/daemon/test_boot_audit_module.py -v -p no:cacheprovider`
Expected: 3 passed. (If `test_boot_refused_error_is_single_definition` FAILS, the re-import in Task 1 Step 5 is wrong — `_commands` defined a second `_BootRefusedError` instead of re-importing.)

- [ ] **Step 3: Verify `_boot_audit.py` hits per-file 100% with no pragmas**

Run: `grep -n "pragma: no cover" src/alfred/cli/daemon/_boot_audit.py; echo "pragmas=$?"`
Expected: no matches (`pragmas=1`) — the anti-pragma rule holds.
Run: `uv run pytest tests/unit/cli/daemon -q -p no:cacheprovider --cov=alfred.cli.daemon._boot_audit --cov-branch --cov-report=term-missing --cov-fail-under=0 && uv run coverage report --include='*/alfred/cli/daemon/_boot_audit.py' --fail-under=100`
Expected: `_boot_audit.py` at 100% (0 Miss, 0 BrPart); the `--fail-under=100` report exits 0.

- [ ] **Step 4: Add the gate to the unit-coverage job**

In `.github/workflows/ci.yml`, immediately after the "Daemon control-plane trust-boundary 100% line+branch coverage" step (ends ~line 281), add:

```yaml

      - name: Daemon boot-audit 100% line+branch coverage
        # #256 PR-1: ``_boot_audit.py`` is the extracted daemon audited-refusal
        # + lifecycle-emit leaf (``_refuse_boot`` / ``_emit_or_quarantine`` /
        # ``_emit_ready`` / ``_emit_going_down`` / ``LifecycleBroadcaster``). The
        # fail-closed refusal MECHANISM: a coverage hole could ship an un-exercised
        # refusal / audit-unwritable-quarantine branch. Fully covered by the unit
        # tier (tests/unit/cli/daemon/), no root/Postgres, so gating on unit-only
        # ``.coverage`` is sound. The combined ``coverage-gates`` job names it too
        # (two-gates pattern — keep BOTH in sync when this file changes).
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/cli/daemon/_boot_audit.py') != ''
        run: |
          uv run coverage report \
            --include='src/alfred/cli/daemon/_boot_audit.py' \
            --fail-under=100
```

- [ ] **Step 5: Add the gate to the combined `coverage-gates` job (two-gates pattern)**

In `.github/workflows/ci.yml`, after the "Daemon control-plane trust-boundary 100% line+branch coverage (combined)" step (~line 1583), add the sibling combined step:

```yaml

      - name: Daemon boot-audit 100% line+branch coverage (combined)
        # #256 PR-1: sibling of the unit-job gate above (two-gates pattern). The
        # extracted daemon boot-audit refusal leaf. Keep BOTH in sync.
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/cli/daemon/_boot_audit.py') != ''
        run: |
          uv run coverage report \
            --include='src/alfred/cli/daemon/_boot_audit.py' \
            --fail-under=100
```

Match the surrounding steps' exact indentation and the `.coverage`-source assumption of the combined job (copy the shape of the adjacent control-plane combined step, adjusting only name + `--include` path).

- [ ] **Step 6: Lint the workflow + commit**

Run: `uv run pytest tests/unit/cli/daemon/test_boot_audit_module.py -q -p no:cacheprovider`
Expected: 3 passed.

```bash
git add .github/workflows/ci.yml tests/unit/cli/daemon/test_boot_audit_module.py
git commit -m "test(daemon): per-file 100% gate + single-definition guard for _boot_audit (#256)"
```

---

### Task 4: Docstring hygiene + full-suite verification + open PR

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (trim the module docstring's now-relocated steps if it over-claims)

- [ ] **Step 1: Reconcile the `_commands.py` module docstring**

Read `_commands.py` lines 1–22. The boot-sequence narrative still describes the overall boot; it stays. Only adjust a sentence if it claims a symbol now lives here that moved (e.g. if it says "this module refuses via `_refuse_boot`"). Keep edits minimal — the orchestration still lives in `_commands.py`. The new `_boot_audit.py` already carries its own module docstring (Task 1).

- [ ] **Step 2: Full unit suite + coverage floor**

Run: `uv run pytest tests/unit -q -p no:cacheprovider`
Expected: all pass; aggregate coverage ≥ 75% (unchanged — code moved, not deleted).

- [ ] **Step 3: Release-blocking adversarial suite**

Run: `uv run pytest tests/adversarial -q -p no:cacheprovider`
Expected: all pass (the boot-refusal branches are fail-closed security surface; a move must not regress them).

- [ ] **Step 4: Full quality gate**

Run: `make check`
Expected: lint + format + type + unit all green. Check `$?` explicitly (do not pipe to `tail`, which masks the exit code).

- [ ] **Step 5: Commit any docstring edit, push, open the PR**

```bash
git add -A && git commit -m "docs(daemon): reconcile _commands docstring after _boot_audit split (#256)" || echo "no docstring change needed"
git push -u origin refactor/256-daemon-boot-split
gh pr create --base main --title "refactor(daemon): extract _boot_audit.py + per-file 100% gate (#256)" \
  --body "PR-1 of #256: extract the audited-refusal + lifecycle-emit leaf from _commands.py. Pure move (no behaviour change), 7 seams re-imported into _commands (all monkeypatch seams + cross-module imports unchanged), i18n catalog re-homed, per-file 100% gate added in both CI jobs. See docs/superpowers/specs/2026-07-03-daemon-commands-boot-refactor-design.md. Refs #256."
```

- [ ] **Step 6: Review + merge (per standing cadence)**

Run `/review-pr` (full fleet, security always) + CodeRabbit. Resolve every thread. CR is quota-throttled + `dismiss_stale_reviews` on: arm `gh pr merge <N> --rebase --auto`, wait out the rate-limit window, one clean `@coderabbitai review`. Never `--admin`. On all-green + no-unresolved-threads, the auto-merge fires (plain rebase).

---

## Self-Review

**1. Spec coverage** — every PR-1 requirement in the spec maps to a task:

- Leaf-first extraction of `_boot_audit.py` (spec "PR-1") → Task 1.
- `LifecycleBroadcaster` + exit constants + `_BootRefusedError` homed in `_boot_audit`; single definition + re-import; post-move exit-code assertion (spec `arch-001` / `sec-004`) → Task 1 (move) + Task 3 (assertion test).
- Two-commit reviewable move (`devex-001`) → Task 1 Steps 3–8.
- Dead-seam bite-proof (`sec-001`) → N/A-with-justification: measured that no test patches the moved refusal/emit seams; `LifecycleBroadcaster` keeps class identity via re-import (Task 1 Step 7 confirms the suite passes unchanged). Recorded so a reviewer sees it was checked, not skipped.
- Anti-pragma rule (`sec-003`) → Task 3 Step 3 (grep asserts zero pragmas).
- Measure-before-gating (`rev-002`) → done during planning (cluster already 100%); Task 3 Step 3 re-confirms.
- Per-file 100% gate in BOTH jobs (two-gates pattern) → Task 3 Steps 4–5.
- Per-PR i18n catalog regen (`i18n-001`) → Task 2.
- Doc-path repoints (`docs-002`) → Task 4 Step 1 (module docstring; `comms.md` is a PR-3 concern, not touched here).
- Adversarial green + `make check` + `/review-pr` → Task 4.

**2. Placeholder scan** — no TBD/TODO; every code step shows exact content or exact source line ranges for a verbatim move; every command has an expected result.

**3. Type consistency** — the `Produces` interface signatures match the source (verified against `_commands.py` @ `92482030`): `_BootRefusedError(code: int)`/`.code`, `_refuse_boot(...) -> NoReturn`, the `_emit_*` keyword-only signatures. The re-import list (7 names) matches the measured call sites; `_invoke_boot_failed` correctly excluded (no external caller, no test ref).

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-07-03-256-pr1-boot-audit-extraction.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
