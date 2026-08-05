# ADR-0061 — The declared Python floor diverges from the enforced floor

- **Status**: Accepted
- **Date**: 2026-08-04
- **Slice**: #568 (restore Dependabot's three dead Python channels)
- **Relates to**: [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)
  (the quarantine-child reachable-import-surface bound that `alfred._python_floor` now
  lives inside, per `src/alfred/__init__.py`), issue
  [#568](https://github.com/alfred-os/AlfredOS/issues/568)

## Context

`pyproject.toml` and `uv.lock` both pinned `requires-python = ">=3.14.6"` — a patch-level
specifier, added to record that CPython 3.14.0-3.14.4 generate a broken
`__setattr__`/`__delattr__` for `@dataclass(frozen=True, slots=True)`: assigning an
*unknown* attribute on a frozen+slots instance raises a spurious `TypeError` instead of
`FrozenInstanceError`/`AttributeError` (CPython gh-105936, fixed by GH-144021, reaching the
3.14 series via GH-148469 in 3.14.5 and backported to 3.13 via GH-148476 — so this is
long-standing, not a 3.14-only regression). The repository cited a different, unrelated
issue — gh-135228, "slot dataclasses classes leak original class" — for this floor from
PR #303 until #568 corrected it.

Dependabot resolves Python at **series** granularity (`3.10.*` … `3.14.*`), not patch
granularity. A patch-level `requires-python` makes it abort file-fetching with
`tool_version_not_supported` — silently, with no PR, no failed check, and no alert other
than the workflow's own run history. That is what happened here: last successful run
2026-06-19, first failure 2026-06-21T08:26:31Z, 20 consecutive failures by the time #568
was filed. It killed three channels at once, because all three read the same field:
dependency-graph submission, Dependabot security updates, and the weekly `pip` updater.
The security-update channel is the one that should have opened PRs for the aiohttp and
GitPython CVEs fixed in #562; only Trivy caught them, and only because it scans
independently of the dependency graph.

## Decision

`pyproject.toml` and `uv.lock` declare a series-level `requires-python = ">=3.14"`, so
Dependabot can resolve and submit the graph. The real floor — 3.14.6, held there because
that is the only patch any CI lane exercises — is enforced at import time by
`alfred._python_floor.enforce()`, called from `src/alfred/__init__.py`.

## Alternatives considered

### Option A — Keep the patch floor, abandon Python graph scanning

Leaves `requires-python = ">=3.14.6"` in place and accepts that Dependabot will never
resolve it. Rejected: it re-kills all three channels forever rather than for 44 days, and
the security-update channel is a real detection layer, not a redundant one — Trivy alone
already missed the window between the CVE landing and #562's manual fix.

### Option B — Self-submit the dependency graph from our own workflow

A repo-owned workflow could push a dependency-submission-API payload, sidestepping
Dependabot's resolver entirely. Rejected as a **half fix**: the security-update and
`pip`-updater channels are Dependabot Updates jobs, not graph consumers — they read
`requires-python` themselves during their own resolution pass, so self-submission would
revive the graph channel while leaving the other two dead.

## Consequences

### Positive

- All three channels resolve again: Dependabot can parse `>=3.14`, submit the graph, and
  run its security-update and `pip` update passes against real dependency data.
- The floor citation is corrected in the same change: gh-105936, not gh-135228, and the
  affected range is 3.14.0-3.14.4 (measured on 3.14.0 and 3.14.4), not 3.14.0-3.14.5.
- Nothing security-relevant is surrendered by relaxing the declared specifier. gh-105936
  only breaks *unknown*-attribute assignment on a frozen+slots instance; a declared
  field still raises `FrozenInstanceError` correctly on the affected patches, and no
  production call site catches `FrozenInstanceError` today.

### Negative

- **Install-time refusal is lost.** `uv sync` under the old patch-level specifier named
  the interpreter it found, the version it required, and its own authority to refuse, all
  at the moment a developer ran the command — strictly better UX than what replaces it.
  The replacement is a loud import-time `UnsupportedPythonError` whose last line is the
  bare closed-vocabulary key `daemon.boot.interpreter_below_floor`, written so
  `bin/alfred-plugin-launcher.sh` can classify it into a signed
  `supervisor.plugin.sandbox_refused` audit row — a machine-readable contract, not
  operator prose, and correspondingly less immediately readable at a bare terminal.
- **The declared and enforced floors can now drift independently** — nothing stops a
  future edit to `pyproject.toml` or `uv.lock` from silently reintroducing a patch-level
  specifier, or from disagreeing with each other. Constrained, not eliminated, by two
  detectors added alongside this decision:
  `tests/unit/meta/test_requires_python_is_dependabot_resolvable.py` (series-level, and
  both manifests agree) and the `make lockcheck` gate (`uv lock --check`), wired into
  `make check`.
- The freshness monitor (`.github/workflows/dependency-graph-freshness.yml`) measures only
  two liveness signals, not three: Dependabot's security-update and weekly-`pip` channels
  are separate commands inside one workflow (`282449388`), so the Actions runs API reports
  one shared conclusion for both. That shared conclusion is usually **not about Python at
  all** — the same workflow also runs the `github-actions` and `docker` ecosystems from
  `.github/dependabot.yml`, and those run far more often, so the workflow's single latest
  conclusion is most often theirs, not the Python channels'. This is why the monitor filters
  to runs whose `display_title` starts with `uv in` rather than trusting
  `.workflow_runs[0]` unfiltered — confirmed live: on 2026-08-02 and 2026-08-03 the
  unfiltered conclusion was a `github_actions in /` success while the `uv` channel was
  actively failing. Splitting security-update from weekly-`pip` within the filtered `uv`
  runs still needs per-job inspection, tracked as a follow-up rather than claimed here.

### Neutral

- `.python-version` stays `3.14.6` — CI, `mypy`, and `pyright` all continue to target the
  exact patch already exercised; only the two manifests' `requires-python` field changed
  scope.
- No runtime behaviour changes for **CPython** already at or above 3.14.6; the guard is a
  no-op there. The refusal path is exercised on any interpreter below the enforced floor,
  which the relaxed declared floor now permits `uv sync` to install. A second guard,
  `alfred._python_floor.enforce_implementation()`, refuses any non-CPython implementation
  regardless of version — PyPy at 3.14.6+ still trips it, because gh-105936 is a CPython
  `dataclasses` code-generation defect and the refusal message's claim is specifically about
  CPython, not just the version number.

## References

- [#568](https://github.com/alfred-os/AlfredOS/issues/568) — the issue
- `docs/superpowers/plans/2026-08-04-568-dependabot-python-channels.md`
- `docs/superpowers/specs/2026-08-04-568-dependabot-python-graph-design.md`
- `src/alfred/_python_floor.py` — the enforced floor
- `tests/unit/test_frozen_slots_dataclass_regression_guard.py` — the behavioural regression
  guard for gh-105936
- #562 — the aiohttp/GitPython CVE fix that Trivy caught alone, while the dead
  security-update channel should have caught it too
