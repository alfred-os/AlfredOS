---
description: 'Review an AlfredOS pull request with a team of specialist agents and CodeRabbit.'
targets: ['*']
---

# Review Pull Request

target_pr = $ARGUMENTS

If no PR number is provided, use the PR of the current branch.

Use the `review-pr` skill. It dispatches the nine always-include reviewers (architect, reviewer, test-engineer, security-engineer, error, performance, docs, i18n, devex) plus the matching subsystem-engineer(s) based on changed paths, and runs CodeRabbit CLI in parallel for an independent static-analysis pass.

Each reviewer writes structured findings to a per-reviewer JSON file. The skill aggregates everything into a severity-grouped summary with file/line pointers.

No auto-fix loop in v1. After surfacing findings, the engineer agent (or human) addresses them, then re-run `/review-pr` until clean.
