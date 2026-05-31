#!/usr/bin/env sh
# bin/alfred-state-git-seed.sh — idempotent state.git init + main-branch seeding.
#
# Called by bin/alfred-setup.sh via:
#   docker compose run --rm --entrypoint /bin/sh alfred-core /app/bin/alfred-state-git-seed.sh
#
# devops-001: invoked with --entrypoint /bin/sh to bypass the `alfred`
#   ENTRYPOINT. `alfred sh -c "..."` would land as an invalid alfred
#   subcommand because the entrypoint absorbs the first argv.
# devops-009: a dedicated script avoids the triple-nested shell escaping
#   that an inline `sh -c "..."` invocation would require to express the
#   idempotency guards below.
#
# `alfred plugin grant init` (PR-S3-3) requires state.git to exist and have
# a seeded main branch. Without this, every plugin load fails with the
# message returned by t("bootstrap.capability_gate_unseeded") (spec §15.4
# step 2). Safe to re-run: `git init --bare` is a no-op on an existing
# bare repo, and the rev-parse guard skips the seed when main is already
# present.
set -eu

STATE_GIT_PATH="${STATE_GIT_PATH:-/var/lib/alfred/state.git}"

if [ "$(git -C "${STATE_GIT_PATH}" rev-parse --is-bare-repository 2>/dev/null || echo 'false')" = "true" ]; then
  echo "state.git already exists as bare repo at ${STATE_GIT_PATH}; skipping init."
else
  # Bare-repo predicate via OUTPUT value (not exit code) — `rev-parse
  # --is-bare-repository` exits 0 for non-bare Git repos too, just
  # prints "false". The `|| echo 'false'` catches the not-a-repo case
  # so an empty Docker-volume directory falls through to init (devops-008).
  git init --bare "${STATE_GIT_PATH}"
  echo "Initialised bare state.git at ${STATE_GIT_PATH}."
fi

# Seed main branch if not present. The rev-parse --verify guard is the
# exact predicate pinned by tests/integration/test_state_git_init.py — a
# fresh bare repo exits non-zero (so the seed runs), a previously-seeded
# repo exits zero (so the seed is skipped).
if ! git -C "${STATE_GIT_PATH}" rev-parse --verify refs/heads/main >/dev/null 2>&1; then
  WORK=$(mktemp -d)
  # The clone is throwaway scratch — we never push anything but the
  # initial empty commit. trap ensures the temp dir is cleaned up even if
  # the seed flow aborts midway.
  trap 'rm -rf "${WORK}"' EXIT INT TERM
  git clone "${STATE_GIT_PATH}" "${WORK}/clone"
  git -C "${WORK}/clone" config user.email 'alfred-setup@localhost'
  git -C "${WORK}/clone" config user.name 'alfred-setup'
  git -C "${WORK}/clone" commit --allow-empty -m 'Initial empty commit (alfred-setup)'
  git -C "${WORK}/clone" push origin HEAD:main
  echo "Seeded main branch in state.git."
else
  echo "main branch already exists in state.git; skipping seed."
fi
