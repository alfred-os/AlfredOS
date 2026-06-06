# Required status checks on `main`

This file is the **canonical, version-controlled manifest** of CI checks that must pass before a PR can merge to `main`. The actual enforcement lives in GitHub branch protection (Settings → Branches → `main` → "Require status checks to pass"); this file is the human-readable mirror.

**Why have this file**: branch-protection config is invisible to PRs that should be updating it, not searchable from the repo, and easily out of sync with the YAML that emits the checks. Every change to required checks lands in the same PR as the workflow change that produced them, so the diff is reviewable here.

## How to read the table

- **Check name** — the exact string GitHub matches against the branch-protection list. Comes from the job's `name:` field in the workflow YAML.
- **Workflow** — the file path of the YAML that emits this check.
- **Job key** — the job's YAML key (used in `jobs:`). For navigating the workflow file, not for branch protection.
- **Active since** — the date the check was added to the required list (not the date the workflow was merged).
- **Rationale** — one sentence on why this is required (vs informational).

## How to update this file

When you add a new gating workflow, follow [`.rulesync/skills/author-gating-workflow/SKILL.md`](../../.rulesync/skills/author-gating-workflow/SKILL.md). After the workflow merges and you run `gh api POST .../contexts`, also append a row here in a follow-up PR (or amend the original PR before merge if your branch hasn't been merged yet).

When you remove a required check: same flow in reverse — `gh api -X DELETE .../contexts` and update this file.

## Currently required

| Check name | Workflow | Job key | Active since | Rationale |
|---|---|---|---|---|
| `Conventional commit format` | `.github/workflows/pr-validate-commits.yml` | `conventional-commits` | 2026-05-25 | Every commit subject must follow `<type>[(<scope>)][!]: <description> (#NN)` so the commit log stays parseable and traceable to an issue. |
| `No autosquash commits` | `.github/workflows/pr-validate-commits.yml` | `no-autosquash` | 2026-05-25 | `fixup!` / `squash!` / `amend!` commits must be squashed via `make autosquash` before merge — they're scaffolding, not history. |
| `No merge commits` | `.github/workflows/pr-validate-commits.yml` | `no-merge-commits` | 2026-05-25 | PRs are rebased onto main, not merged. Merge commits in a PR mean someone synced via `git merge` instead of `git rebase`. |
| `Gitleaks (secrets)` | `.github/workflows/pr-validate-security.yml` | `gitleaks` | 2026-05-25 | Block PRs that introduce secrets / credentials / API tokens. Scans the PR diff only (cheap). |
| `Zizmor (workflow security)` | `.github/workflows/pr-validate-security.yml` | `zizmor` | 2026-05-25 | Block PRs that introduce GitHub Actions security issues (workflow injection, unpinned uses, artipacked credentials, excessive token permissions). |
| `Semgrep (SAST)` | `.github/workflows/pr-validate-security.yml` | `semgrep` | 2026-05-25 | Block PRs that introduce findings from the `p/security-audit` + `p/secrets` + `p/github-actions` rulesets. Returns ~0 findings today (no Python code yet); coverage activates as Slice 1+ lands code. |
| `Trivy (IaC + filesystem)` | `.github/workflows/pr-validate-security.yml` | `trivy` | 2026-05-25 | Block PRs that introduce CRITICAL/HIGH vulnerabilities in the filesystem (secrets, license issues, future `uv.lock` deps) or IaC misconfigurations (future Dockerfile / docker-compose / workflow files). |
| `CodeQL (Python)` | `.github/workflows/codeql.yml` | `analyze` | 2026-05-25 | Block PRs that introduce findings from CodeQL's `security-and-quality` query suite (data-flow-sensitive bugs Semgrep's rule-based engine misses). Free for public repos via GitHub Advanced Security. Skips when there's no Python source yet (pre-Slice-1). |

## Pending required (workflow merged, awaiting `gh api POST .../contexts`)

These checks are emitted by their workflow but not yet in the branch-protection required list. Per the [author-gating-workflow skill](../../.rulesync/skills/author-gating-workflow/SKILL.md) Step 4: after the workflow merges and runs at least once on a PR, append each name via `gh api`, then move the row to "Currently required" above with today's date.

> **Before promoting `Hook dispatch perf gate` to a required check:**
> The workflow `.github/workflows/perf.yml` uses a `paths:` filter (it only triggers
> when changes touch `src/alfred/hooks/**`, `src/alfred/memory/episodic.py`,
> `tests/perf/**`, `pyproject.toml`, or the workflow file). If promoted to a required
> check as-is, PRs that don't touch those paths would have the check stay in "Pending"
> and the PR would be blocked from merging
> (see [GitHub docs](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)).
>
> Mitigation options (decide before promotion):
>
> 1. Add a companion always-triggered workflow that reports the same check name
>    and short-circuits to success on off-path PRs.
> 2. Drop the `paths:` filter from `perf.yml` (lets the workflow run on all PRs;
>    higher CI cost, but simpler).
> 3. Use `actions/changed-files` inside a single job to gate the actual bench run
>    while always reporting the check name.

| Check name | Workflow | Job key | Rationale | Promote after |
|---|---|---|---|---|
| `Ruff format` | `.github/workflows/pr-validate-python.yml` | `ruff-format` | Enforces `ruff format --check` (formatter no-op) so the formatter is the source of truth, not reviewer time. Skips when `src/` / `tests/` have no `.py` files. | This PR merges + workflow runs on any subsequent PR. |
| `Ruff lint` | `.github/workflows/pr-validate-python.yml` | `ruff-lint` | Enforces `ruff check` with the strict rule set (E, F, I, B, UP, N, S, ARG, RET, SIM, PTH, DTZ, FBT, PIE, RUF). Skips when no Python source. | Same as above. |
| `Mypy (strict)` | `.github/workflows/pr-validate-python.yml` | `mypy` | Primary type-checker. Enforces `mypy --strict` on `src/`. Skips when no Python source. | Same as above. |
| `Pyright` | `.github/workflows/pr-validate-python.yml` | `pyright` | Secondary type-checker. Catches data-flow patterns mypy misses. Skips when no Python source. | Same as above. |
| `Markdown lint` | `.github/workflows/ci.yml` | `markdown` | Documentation linting via `markdownlint-cli2@0.14.0` with the repo-canonical `.markdownlint-cli2.jsonc` config (rules tuned for AlfredOS docs prose in PR #186). Catches structural regressions in `docs/`, `ADRs`, runbooks, and plan-docs. | This PR merges + workflow runs on any subsequent PR. |
| `Python (lint, types, unit)` | `.github/workflows/ci.yml` | `python` | Canonical Python check: ruff lint + ruff format-check + mypy --strict + pyright + unit tests + per-subsystem 100% coverage gates (`security/*`, `hooks/*`, `plugins/*`, `web_fetch/*`). Subsumes `pr-validate-python.yml`'s former `Pytest` job (removed in this PR — it ran without coverage and presented a misleading parallel green signal). | This PR merges + workflow runs on any subsequent PR. |
| `Integration` | `.github/workflows/ci.yml` | `integration` | Integration test suite under `tests/integration/` against real testcontainers (Postgres, Redis). Appends coverage data to the artifact the `coverage-gates` job consumes. | Same as above. |
| `Coverage gates (combined unit + integration)` | `.github/workflows/ci.yml` | `coverage-gates` | The CLAUDE.md hard-rule-#7 trust-boundary 100% gate. Combines unit + integration coverage and enforces 100% line+branch on `security/*`, `hooks/*`, plugins trust-boundary files, and the web-fetch trust-boundary list. Was paper-only through ~6 months of accumulated debt (broken `coverage combine` invocation dropped unit data — fixed in #200); promoted now because PR #200's fix lets the union actually fire. | Same as above. **Requires #200 to land first** so the gate isn't reading integration-only data. |
| `Smoke (end-to-end)` | `.github/workflows/ci.yml` | `smoke` | End-to-end TUI smoke against an in-process mock provider (and the real provider when a non-placeholder `ALFRED_SMOKE_PROVIDER_KEY` is configured). Pins the TUI → orchestrator → episodic-write → audit-row contract. | Same as above. **Requires #199 to land first** (the `T1` trust-tier assertion fix). |
| `Setup script smoke (ubuntu-latest)` | `.github/workflows/ci.yml` | `setup-script-smoke` | `bin/alfred-setup.sh --dry-run` on ubuntu-latest. Catches bash-portability and prereq-check regressions in the operator-facing setup script. | Same as above. |
| `Setup script smoke (macos-latest)` | `.github/workflows/ci.yml` | `setup-script-smoke` | `bin/alfred-setup.sh --dry-run` on macos-latest. Catches bash 3.2 / BSD-coreutils regressions the ubuntu leg won't see. Uses a no-op `docker` shim (PR #191) so `--dry-run` reaches the bash logic without needing a real daemon. | Same as above. |
| `i18n catalog freshness` | _(to be authored — `.github/workflows/pr-validate-i18n.yml`)_ | _(planned)_ | CLAUDE.md hard rule #4: `pybabel extract` runs in pre-commit; `pybabel compile --check` runs in CI. Catalog drift (extracted msgids missing from `.po`, or `.po` failing to compile) fails the build. Not yet authored — tracked as a Slice 1 follow-up. | After the i18n workflow PR merges. |
| `Hook dispatch perf gate` | `.github/workflows/perf.yml` | `perf` | Slice-2.5 spec §5: release-blocking dispatch-overhead gate for the pluggable-hooks subsystem. Asserts the p99 delta over a per-runner baseline is < 100µs for empty-hookpoint dispatch and < 1ms for a 5-subscriber pre chain (empirical budgets calibrated in `tests/perf/test_hook_dispatch_perf.py`). Workflow carries NO `continue-on-error` — release-blocking from day one. CI invokes `make test-perf` (Makefile is single-source-of-truth for the invocation shape); the workflow sets `ALFRED_TEST_PERF_FORCE=1` so the Makefile's host-load guard (refuses at load ≥ 1.0× CPUs, warns at 0.7×) defers to CI's explicit "runner is fine" signal. Contributors running `make test-perf` locally can set the same env var (`1` / `true` / `yes`, case-insensitive) to skip the guard. **Before promoting:** see the path-filter caveat above the table — `perf.yml`'s `paths:` filter would block off-path PRs unless mitigated. | This PR merges + workflow runs on any subsequent PR. |

**Post-Slice-1 cleanup**: once `src/alfred/**/*.py` lands, the `srccheck` short-circuit guards at the top of each Python gate's job should be **removed** (not toggled). A future layout-change that breaks the find pattern would otherwise silently re-enable the no-op. Tracked alongside the Task 17 (PR + CI wiring) deliverable.

## Not currently required (but exists)

| Check name | Workflow | Why not required |
|---|---|---|
| `CodeRabbit` | (external service, no workflow file) | CodeRabbit has occasional service blips that surface as non-success status. We gate via `request_changes_workflow: true` in `.coderabbit.yaml` + the 1-approving-review rule instead, so an outage means "manually approve" rather than "repo unmergeable". |

## On bypass

Pre-push hooks (`lefthook`) can be skipped with `LEFTHOOK=0 git push`. This bypass is local-only — **the required status checks listed above cannot be bypassed**; they run on every PR and the merge button is blocked until they pass. Treat `LEFTHOOK=0` as functionally equivalent to `--no-verify`: emergency-only, never a habit.

## Audit

To compare this file against the live state:

```bash
gh api repos/alfred-os/AlfredOS/branches/main/protection \
  --jq .required_status_checks.contexts
```

The output should be a JSON array of exactly the check names in the "Currently required" table. Drift between the two is a process bug — fix the side that's wrong and open a PR.
