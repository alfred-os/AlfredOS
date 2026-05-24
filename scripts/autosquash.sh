#!/usr/bin/env bash
# autosquash.sh — Squash all fixup! commits into their targets using git rebase --autosquash.
#
# Conflict resolution always restores the pre-rebase HEAD version of every
# conflicted file, guaranteeing the final tree is identical to the pre-rebase
# HEAD regardless of intermediate rebase state.
#
# Usage: scripts/autosquash.sh [--base <ref>]
#   --base <ref>   Override the rebase base (default: merge-base with main/master)
#
# Exits 0 on success (or when there is nothing to squash).
# Exits 1 on failure (tree mismatch, rebase stuck, no base found).

set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
CUSTOM_BASE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --base requires a ref" >&2
        exit 1
      fi
      CUSTOM_BASE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Anchor to repo root
#
# All subsequent path-based operations (mkdir, redirect to "$path", ln -s,
# git add) operate on the repo-root-relative paths returned by `git diff
# --name-only --diff-filter=U`. If this script were invoked from a subdir,
# those operations would target the wrong on-disk location — e.g. running
# `scripts/autosquash.sh` from `scripts/` would try to write back into
# `scripts/scripts/...`. Anchoring once here keeps the rest of the script
# location-agnostic.
# ---------------------------------------------------------------------------
TOPLEVEL=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "ERROR: Not inside a git working tree." >&2
  exit 1
}
cd "$TOPLEVEL"

# ---------------------------------------------------------------------------
# Step 1: Preflight
# ---------------------------------------------------------------------------
if ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "ERROR: Working tree is dirty (modified, staged, or untracked files). Stash or commit your changes first." >&2
  exit 1
fi

if [[ -n "$CUSTOM_BASE" ]]; then
  BASE="$CUSTOM_BASE"
else
  # Try local refs first, then fall back to remote-tracking refs so this works
  # in fresh clones / linked worktrees that haven't created local `main` yet.
  BASE=$(
    git merge-base HEAD main 2>/dev/null ||
    git merge-base HEAD master 2>/dev/null ||
    git merge-base HEAD origin/main 2>/dev/null ||
    git merge-base HEAD origin/master 2>/dev/null ||
    true
  )
fi

if [[ -z "$BASE" ]]; then
  echo "ERROR: Cannot find merge-base with main, master, origin/main, or origin/master." >&2
  exit 1
fi

# Validate that BASE resolves to an actual commit. Without this, an invalid
# --base value would cause `git log "$BASE"..HEAD` to error to stderr, the
# `|| true` would mask the failure, AUTOSQUASH_COUNT would land at 0, and
# the script would exit cleanly with "Nothing to squash" — silently treating
# an invalid input as a no-op. Fail loud instead.
if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
  echo "ERROR: Base ref does not resolve to a commit: $BASE" >&2
  exit 1
fi

# `git rebase --autosquash` recognises fixup!, squash!, AND amend! prefixes —
# count all three so a branch containing only squash!/amend! commits doesn't
# get a false "Nothing to squash" verdict.
AUTOSQUASH_COUNT=$(git log --oneline "$BASE"..HEAD | grep -cE '^[0-9a-f]+ (fixup!|squash!|amend!) ' || true)
if [[ "$AUTOSQUASH_COUNT" -eq 0 ]]; then
  echo "Nothing to squash — no autosquash (fixup!/squash!/amend!) commits found between $BASE and HEAD."
  exit 0
fi

BEFORE_COUNT=$(git log --oneline "$BASE"..HEAD | wc -l | tr -d ' ')
echo "Found $AUTOSQUASH_COUNT autosquash commit(s) in $BEFORE_COUNT total commits."

# ---------------------------------------------------------------------------
# Step 2: Record pre-rebase state
# ---------------------------------------------------------------------------
GITDIR=$(git rev-parse --git-dir)

# Preflight guard: refuse to start when an unrelated rebase is already
# in progress. Without this check we would record the current HEAD,
# resolve / abort that pre-existing sequencer state at Step 4, and
# potentially destroy an unrelated history rewrite the adventurer was
# halfway through. Fail fast with a clear error instead.
if [[ -d "$GITDIR/rebase-merge" || -d "$GITDIR/rebase-apply" ]]; then
  echo "ERROR: A rebase is already in progress." >&2
  echo "       Finish (git rebase --continue) or abort (git rebase --abort)" >&2
  echo "       it before running autosquash." >&2
  exit 1
fi

BEFORE=$(git rev-parse HEAD)
BEFORE_TREE=$(git rev-parse "HEAD^{tree}")
echo "Pre-rebase HEAD : $BEFORE"
echo "Pre-rebase tree : $BEFORE_TREE"

# ---------------------------------------------------------------------------
# Step 3: Run autosquash rebase
# ---------------------------------------------------------------------------
# Capture rebase exit explicitly so set -e doesn't abort on the expected
# non-zero exit when there are conflicts (handled in Step 4 below).
if GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash "$BASE"; then
  REBASE_EXIT=0
else
  REBASE_EXIT=$?
fi

in_rebase() {
  [[ -d "$GITDIR/rebase-merge" ]] || [[ -d "$GITDIR/rebase-apply" ]]
}

# ---------------------------------------------------------------------------
# Step 4: Resolve conflicts
# ---------------------------------------------------------------------------
# Distinguish "rebase paused on conflict" (in_rebase == true → resolve) from
# "rebase blew up before creating any state" (REBASE_EXIT != 0 but no
# rebase-merge/rebase-apply dir → fail loud). The old combined guard masked the
# latter as a successful "Conflicts resolved after 0 iterations" run.
if in_rebase; then
  echo "Entering conflict resolution loop..."
  iter=0
  while in_rebase && [[ $iter -lt 200 ]]; do
    iter=$((iter + 1))

    mapfile -t conflicts < <(git diff --name-only --diff-filter=U 2>/dev/null || true)

    if [[ ${#conflicts[@]} -eq 0 ]]; then
      echo "  [iter $iter] No conflicts — skipping empty commit..."
      GIT_EDITOR=/usr/bin/true git rebase --skip 2>&1 || true
      continue
    fi

    echo "  [iter $iter] Resolving ${#conflicts[@]} conflict(s): ${conflicts[*]}"
    for path in "${conflicts[@]}"; do
      if git cat-file -e "${BEFORE}:${path}" 2>/dev/null; then
        # Recreate parent directory in case the rebase step removed or
        # renamed the folder — `git show` can't redirect into a missing
        # path and would break the resolution loop.
        mkdir -p "$(dirname "$path")"
        # Restore the pre-rebase version. Mode-aware so we preserve symlinks
        # (mode 120000) and executable bits (mode 100755). Plain
        # `git show "${BEFORE}:${path}" > "$path"` would silently turn a
        # tracked symlink into a regular file containing the link target.
        mode=$(git ls-tree "$BEFORE" -- "$path" | awk '{print $1}')
        # If $path currently exists as a directory in the worktree (D/F flip
        # where $BEFORE has it as a file/symlink), `rm -f` and `git show >`
        # both fail under set -e. `rm -rf` first clears whatever's there, then
        # each branch creates the right thing. Skipped for the 040000 branch
        # because `git checkout -- <path>` handles the swap natively.
        case "$mode" in
          120000)
            # Symlink: target text comes from `git show`; recreate via ln -s.
            target=$(git show "${BEFORE}:${path}")
            rm -rf "$path"
            ln -s "$target" "$path"
            git add "$path"
            ;;
          100755)
            rm -rf "$path"
            git show "${BEFORE}:${path}" > "$path"
            chmod +x "$path"
            git add "$path"
            ;;
          040000)
            # Directory/tree (D/F conflict). `git show > "$path"` would
            # redirect blob content INTO a directory and fail; use
            # `git checkout` to restore the whole subtree atomically.
            # `git checkout <ref> -- <path>` also stages the change.
            git checkout "$BEFORE" -- "$path"
            ;;
          *)
            # Regular file (mode 100644).
            rm -rf "$path"
            git show "${BEFORE}:${path}" > "$path"
            git add "$path"
            ;;
        esac
        echo "    Restored: $path (mode ${mode:-unknown})"
      else
        # `-r` so directory removals work too (path may be a tree in HEAD
        # but absent from $BEFORE during a D/F conflict).
        git rm -rf -- "$path" 2>/dev/null || true
        echo "    Removed: $path"
      fi
    done

    GIT_EDITOR=/usr/bin/true git rebase --continue 2>&1 || true
  done

  if in_rebase; then
    echo "ERROR: Still rebasing after $iter iterations. Aborting." >&2
    git rebase --abort
    # Match Step 5's rollback semantics: D/F conflicts can leave untracked
    # side files even after --abort, so clean them too.
    git clean -fd
    exit 1
  fi
  echo "Conflicts resolved after $iter iteration(s)."
elif [[ $REBASE_EXIT -ne 0 ]]; then
  # Rebase failed before creating any sequencer state (rebase-merge /
  # rebase-apply). Nothing for the conflict loop to do — fail loud rather
  # than silently advancing to the "Conflicts resolved after 0 iterations"
  # / "autosquash complete" success path.
  echo "ERROR: git rebase --autosquash failed before any conflict could be created (exit=$REBASE_EXIT)." >&2
  exit "$REBASE_EXIT"
fi

# ---------------------------------------------------------------------------
# Step 5: Verify final state
#
# The preflight requires a clean working tree. D/F conflicts during rebase can
# leave Git-generated side files behind (e.g. `path~branch-name`) that are
# invisible to the tree hash but visible to `git status`. Enforce the same
# invariant on the way out: tree must match AND working tree must be clean.
# `git clean -fd` removes untracked-but-not-ignored files (consistent with the
# preflight's `--exclude-standard` semantics; ignored files like .env stay put).
# ---------------------------------------------------------------------------
AFTER_TREE=$(git rev-parse "HEAD^{tree}")
if [[ "$AFTER_TREE" != "$BEFORE_TREE" ]]; then
  echo "ERROR: Tree mismatch after rebase!" >&2
  echo "  Before: $BEFORE_TREE" >&2
  echo "  After : $AFTER_TREE" >&2
  echo "Resetting to pre-rebase state." >&2
  git reset --hard "$BEFORE"
  git clean -fd
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "ERROR: Working tree is dirty after rebase (likely D/F-conflict side files)." >&2
  echo "Resetting to pre-rebase state." >&2
  git reset --hard "$BEFORE"
  git clean -fd
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 6: Report
# ---------------------------------------------------------------------------
AFTER_COUNT=$(git log --oneline "$BASE"..HEAD | wc -l | tr -d ' ')
echo ""
echo "autosquash complete:"
echo "  Squashed : $AUTOSQUASH_COUNT autosquash commit(s)"
echo "  Commits  : $BEFORE_COUNT → $AFTER_COUNT"
echo "  Tree     : identical (verified)"
echo ""
git log --oneline "$BASE"..HEAD
