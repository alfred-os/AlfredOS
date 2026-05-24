---
description: 'Review an AlfredOS implementation plan with a team of specialist agents.'
targets: ['*']
---

# Review Plan

target_plan = $ARGUMENTS

If no path is provided, find the most recent file under `docs/superpowers/plans/*.md`.

Use the `review-plan` skill. It dispatches the always-include reviewers (architect, reviewer, test-engineer, security-engineer, error, performance, docs, i18n, devex) plus the matching subsystem-engineer(s) based on the plan's coverage matrix. Each reviewer reads the plan and writes structured findings. The skill aggregates them into a severity-grouped summary.

This is a read-only review. No auto-fix loop. Plans are negotiated, not patched.
