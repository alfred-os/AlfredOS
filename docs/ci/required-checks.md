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

## Pending required (workflow merged, awaiting `gh api POST .../contexts`)

These checks are emitted by their workflow but not yet in the branch-protection required list. Per the [author-gating-workflow skill](../../.rulesync/skills/author-gating-workflow/SKILL.md) Step 4: after the workflow merges and runs at least once on a PR, append each name via `gh api`, then move the row to "Currently required" above with today's date.

| Check name | Workflow | Job key | Added in PR | Rationale |
|---|---|---|---|---|
| `Gitleaks (secrets)` | `.github/workflows/pr-validate-security.yml` | `gitleaks` | #77 | Block PRs that introduce secrets / credentials / API tokens. Scans the PR diff only (cheap). |
| `Zizmor (workflow security)` | `.github/workflows/pr-validate-security.yml` | `zizmor` | #77 | Block PRs that introduce GitHub Actions security issues (workflow injection, unpinned uses, artipacked credentials, excessive token permissions). |
| `Semgrep (SAST)` | `.github/workflows/pr-validate-security.yml` | `semgrep` | #77 | Block PRs that introduce findings from the `p/security-audit` + `p/secrets` + `p/github-actions` rulesets. Returns ~0 findings today (no Python code yet); coverage activates as Slice 1+ lands code. |
| `Trivy (IaC + filesystem)` | `.github/workflows/pr-validate-security.yml` | `trivy` | #77 | Block PRs that introduce CRITICAL/HIGH vulnerabilities in the filesystem (secrets, license issues, future `uv.lock` deps) or IaC misconfigurations (future Dockerfile / docker-compose / workflow files). |
| `CodeQL (Python)` | `.github/workflows/codeql.yml` | `analyze` | #77 | Block PRs that introduce findings from CodeQL's `security-and-quality` query suite (data-flow-sensitive bugs Semgrep's rule-based engine misses). Free for public repos via GitHub Advanced Security. |

## Not currently required (but exists)

| Check name | Workflow | Why not required |
|---|---|---|
| `CodeRabbit` | (external service, no workflow file) | CodeRabbit has occasional service blips that surface as non-success status. We gate via `request_changes_workflow: true` in `.coderabbit.yaml` + the 1-approving-review rule instead, so an outage means "manually approve" rather than "repo unmergeable". |

## Audit

To compare this file against the live state:

```bash
gh api repos/alfred-os/AlfredOS/branches/main/protection \
  --jq .required_status_checks.contexts
```

The output should be a JSON array of exactly the check names in the "Currently required" table. Drift between the two is a process bug — fix the side that's wrong and open a PR.
