---
name: author-gating-workflow
description: >-
  Use when authoring a GitHub Actions workflow that should gate the merge
  button on `main`. Walks through writing the workflow with AlfredOS
  conventions (least-privilege permissions, workflow-injection-safe env
  passing, concurrency caps), opening the PR, promoting the gating jobs to
  required status checks via gh api after merge, and updating the tracked
  required-checks manifest so the gate list stays auditable from the repo.
targets:
  - '*'
---

# Author a gating GitHub Actions workflow

Creating a workflow that *runs* on every PR is easy. Creating one that *blocks* the merge button is a two-step process where step 2 leaves no trace in the repo and is easy to forget. This skill captures both steps.

## When to use

- You're writing a new `.github/workflows/*.yml` that lints, validates, or otherwise emits a pass/fail signal you want to enforce on merges to `main`.
- You're adding a new gating job to an existing workflow.
- You're auditing whether an existing workflow is actually doing its gating job (very common: workflow runs green/red, required-checks list never named it, so the red never blocked anything).

## What you'll produce

1. The workflow YAML at `.github/workflows/<name>.yml`.
2. (After merge) updated branch-protection required-checks list, via `gh api`.
3. A new line in `docs/ci/required-checks.md` documenting what's now required.

## Step 1 — Decide what gates

Not every job in a workflow needs to block the merge button. Examples:

| Job purpose | Gating? |
| --- | --- |
| Lint / type-check / formatter that ALWAYS must pass | ✓ Yes |
| Unit / integration / smoke tests | ✓ Yes |
| Security gate (commit-msg validation, no-fixup, no-merge-commit) | ✓ Yes |
| Coverage gate (e.g. ≥100% on `src/alfred/security/`) | ✓ Yes |
| Post-merge notification (Discord, deploy) | ✗ No (runs on merge, not PR) |
| Telemetry / metrics emit | ✗ No (informational) |
| Optional / experimental check author wants to opt into | ✗ No |

For each gating job, **record the job's `name:` value verbatim** — that's the string you'll add to the required-checks list later. If the job has no `name:`, it'll appear in the checks panel as the job key from the YAML — set a `name:` explicitly to avoid this becoming brittle.

## Step 2 — Write the workflow

Apply the AlfredOS conventions:

```yaml
name: <Human-readable workflow name>

on:
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]

# Pushes to the same PR cancel earlier in-flight runs.
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

# Deny-all baseline; each job opts in to the minimum scope it needs.
permissions: {}

jobs:
  <stable-id>:
    # The `name:` value here is what becomes the required-check string in step 4.
    # Keep it short, stable, human-readable. Changing it is a breaking change to
    # branch protection — the OLD name stays in the required-checks list forever
    # unless removed, and the NEW name is a non-required status until added.
    name: <Gating check name — verbatim future required-checks key>
    runs-on: ubuntu-latest
    timeout-minutes: <a sensible cap, e.g. 5>
    permissions:
      contents: read   # opt in to exactly what's needed
    steps:
      - name: Checkout code
        # Pin actions to a commit SHA (supply-chain hygiene; per zizmor's
        # `unpinned-uses` rule). Comment with the version for human readability.
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
          # No git push from this workflow → don't leave credentials behind.
          # (zizmor's `artipacked` rule.) Add only when actually pushing.
          persist-credentials: false
      - name: <Step name>
        # WORKFLOW-INJECTION SAFE: any github.event.* value goes through `env:`
        # and is read as "$VAR" in shell. NEVER inline-interpolate them as
        # ${{ github.event.x }} inside `run:`.
        # See: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          set -euo pipefail
          # ...your check logic, reading "$BASE_SHA" / "$HEAD_SHA"...
```

**Hard rules** (matches PRD §7 and CLAUDE.md):

- `permissions: {}` at workflow level; each job opts in to the minimum.
- `pull_request` not `pull_request_target` unless you genuinely need cross-fork write access. `pull_request_target` runs the workflow file from the BASE branch and has access to secrets — easy to footgun.
- `concurrency` block with `cancel-in-progress: true` so a force-push doesn't queue stale runs.
- `timeout-minutes` per job — pick a number that's 2× the expected duration, not "no limit".
- Pin every external action to a commit SHA, not `@v4` or `@main`. zizmor's `unpinned-uses` catches this.
- `persist-credentials: false` on `actions/checkout` unless the job genuinely needs to push.
- env-pass-then-quote for any `github.event.*` value; never interpolate `${{ }}` directly in `run:` strings.

## Step 3 — Open the PR

Standard flow:

```bash
git checkout -b issue-<NN>-<slug>
git add .github/workflows/<name>.yml docs/ci/required-checks.md
git commit -m "ci(<scope>): add <name> workflow (#<NN>)"
git push -u origin issue-<NN>-<slug>
gh pr create --title "ci(<scope>): add <name> workflow" --body "..."
```

**Update `docs/ci/required-checks.md` in the same PR** — add a stub line for the new check marked "(pending: not yet added to required list — see step 4 after merge)". The stub lives in the doc so the PR diff makes it visible that this is something that should land as a required check; you flip the stub to active in step 5.

Why this is a stub now and not active: branch protection is per-repo state, not per-branch. You can't add a required check that doesn't exist yet — GitHub rejects names it hasn't seen. So step 4 must wait until the workflow has been merged at least once.

## Step 4 — After merge: promote to required check

Once the PR is merged to main and the workflow has run at least once on a PR (so GitHub knows the check name exists), add it to the required list:

```bash
gh api -X POST repos/<owner>/<repo>/branches/main/protection/required_status_checks/contexts \
  -F 'contexts[]=<Gating check name 1>' \
  -F 'contexts[]=<Gating check name 2>'
```

The `-F 'contexts[]=...'` form **appends** to the existing list — it does NOT replace. Other settings on the protection (review count, linear history, conversation resolution, etc.) are untouched.

Verify:

```bash
gh api repos/<owner>/<repo>/branches/main/protection \
  --jq .required_status_checks.contexts
```

You should see the new names in the array. If you see `[]`, the POST didn't take effect; check that the workflow has run at least once on a PR (the check names need to be visible to GitHub's status-check registry, which requires at least one historical run).

## Step 5 — Flip the stub in `docs/ci/required-checks.md`

Open a small follow-up PR that flips the stub line from "(pending)" to "(active since YYYY-MM-DD)". This is the audit trail entry — without it, the required-checks list is invisible config in GitHub Settings, hard to discover for new contributors and hard to review when it changes.

## Step 6 — Verify gating actually works

Open a deliberately-failing throwaway branch:

```bash
git checkout -b test/gate-validation
# make a change that should fail the new check
git commit -am "test: deliberately failing commit for gate validation"
git push -u origin test/gate-validation
gh pr create --title "test: gate validation (DO NOT MERGE)" --body "Validates new required check rejects the failing case." --draft
```

The PR should show:

- The new check ✗ failed
- "Merge" button blocked with "Required statuses must pass"

Then close the PR and delete the branch. This is a one-time validation per new gate — keeps the "looks like a gate, isn't a gate" failure mode from recurring.

## Hard rules

- **Never `pull_request_target` for first-party PR workflows** unless you genuinely need cross-fork access AND have audited every shell `run:` for injection. The combination of `pull_request_target` + unquoted `${{ github.event.* }}` in shell is the workflow-injection footgun. See: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/
- **Never pin to `@main` or `@v4`** — pin to a full commit SHA. `@v4` is a tag that can be moved by a compromised maintainer; `@main` follows the action's main branch and has no version stability at all.
- **Never grant `contents: write`, `pull-requests: write`, or any write scope** to a gate-only workflow. Gates read git history and report pass/fail; they don't mutate the repo.
- **Never skip Step 5**. The `docs/ci/required-checks.md` manifest is what makes the gate list discoverable.

## Failure modes

- **`gh api POST .../contexts` returns 404 or 422** — the check name hasn't been seen by GitHub yet. Wait for the workflow to run at least once on any PR after the merge, then retry.
- **Workflow runs but checks panel doesn't show the new name** — the job's `name:` field isn't set; GitHub falls back to the job key. Set `name:` explicitly.
- **Check shows as "Skipped" with `pull_request_target`** — the workflow file the runner used came from the BASE branch (`main`), not your PR. This is by design for `pull_request_target`; consider `pull_request` if cross-fork access isn't needed.
- **Workflow has `pull_request` trigger but you're testing across forks** — won't run on PRs from forks; switch to `pull_request_target` only if you've audited the injection surface.
