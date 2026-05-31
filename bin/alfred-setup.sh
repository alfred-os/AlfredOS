#!/usr/bin/env bash
# Idempotent setup script for AlfredOS Slice 1+2.
#
# Usage:
#   bin/alfred-setup.sh             # full setup
#   bin/alfred-setup.sh --dry-run   # check prerequisites only, then exit 0
#
# Safe to re-run any number of times: the .env copy is guarded by an
# existence check, `docker compose build` is a no-op when the cached
# layers are still valid, `alfred migrate` is alembic-idempotent, and
# the operator-add step is gated on a `user list` count.
#
# Slice-2 (PR D2): the script now also bootstraps the operator
# identity, primes the secrets bind-mount directory + file with the
# right perms, exports UID/GID for the compose `user:` substitution,
# and optionally prompts for a Discord snowflake bind followed by an
# `alfred discord verify` probe.
set -euo pipefail

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
fi

step() { printf "\n==> %s\n" "$1"; }
warn() { printf "WARNING: %s\n" "$1" >&2; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

# `require_cmd` errors out with a friendly install hint when a hard
# prereq is missing. `jq` is new for PR D2 — used to parse
# `alfred user list --json` so we can detect the operator-already-exists
# branch idempotently.
require_cmd() {
  local name="$1"
  local hint="$2"
  if ! command -v "$name" >/dev/null 2>&1; then
    fail "$name not found. Install it with: $hint"
  fi
}

# `read_env_var KEY` greps a value out of `.env` without `source`-ing
# the file. Sourcing executes the file as bash, which means `#`
# truncates lines silently and `$()` runs subshells — a pasted line
# could execute arbitrary code. The grep|cut|tr pipeline is safe.
read_env_var() {
  local key="$1"
  if [[ ! -f .env ]]; then
    return 0
  fi
  grep -E "^${key}=" .env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true
}

step "Checking prerequisites"
require_cmd docker "https://docs.docker.com/engine/install/"
# `docker compose version` covers both the v2 subcommand and the
# `command -v docker compose` form (which doesn't actually work — kept
# as a defensive fallback for old setups).
command -v docker compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 \
  || { warn "docker compose not found"; exit 1; }
require_cmd jq "macOS: brew install jq; Debian/Ubuntu: sudo apt install -y jq"

if $dry_run; then
  echo "DRY-RUN: prerequisites OK. Stopping."
  exit 0
fi

step "Ensuring .env exists"
if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "Created .env from .env.example. Edit it before running 'docker compose up'."
  else
    warn ".env.example not found; create .env manually."
  fi
fi

step "Validating ALFRED_DEEPSEEK_API_KEY is set"
# Deliberately NOT `source .env`. Sourcing executes the file as bash, which
# means `#` truncates lines silently, `$()` runs subshells, and an
# operator-pasted line can run arbitrary commands. Instead, we extract just
# the key we care about with a single grep + cut + tr pipeline. The tr -d
# strips surrounding single/double quotes so an operator who wrote
# `ALFRED_DEEPSEEK_API_KEY="sk-..."` is treated the same as the bare form.
if [[ -f .env ]]; then
  # `set -euo pipefail` is in effect: `grep` exits 1 when the key is absent,
  # which would abort the script BEFORE the empty-check below can run and
  # surface the friendly operator message. Use `|| true` so a missing key
  # surfaces as an empty value instead of a hard abort.
  ALFRED_DEEPSEEK_API_KEY=$(grep -E '^ALFRED_DEEPSEEK_API_KEY=' .env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
else
  ALFRED_DEEPSEEK_API_KEY=""
fi
if [[ -z "${ALFRED_DEEPSEEK_API_KEY:-}" ]]; then
  warn "ALFRED_DEEPSEEK_API_KEY is empty. Edit .env and re-run."
  exit 1
fi
# Reject the literal placeholder shipped in .env.example. Catching it here
# (rather than letting it propagate to the provider call) gives operators a
# friendly error before the container even boots. The settings.py validator
# enforces the same invariant inside the app for any path that skips this
# script.
if [[ "${ALFRED_DEEPSEEK_API_KEY}" == "sk-..." ]]; then
  warn "Detected placeholder API key. Edit .env and replace 'sk-...' with a real DeepSeek API key from https://platform.deepseek.com."
  exit 1
fi

step "Building images"
docker compose build

step "Starting alfred-postgres"
docker compose up -d alfred-postgres

step "Waiting for Postgres health"
ready=false
for _ in {1..30}; do
  if docker compose exec -T alfred-postgres pg_isready -U alfred -d alfred >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != "true" ]]; then
  warn "Postgres did not become healthy within 30s. Inspect 'docker compose logs alfred-postgres' and re-run."
  exit 1
fi

step "Running migrations"
# `alfred migrate` is the blessed surface — see src/alfred/cli/main.py.
# Avoids overriding the container ENTRYPOINT with `--entrypoint ""` /
# `sh -c`, which would punch through the operator-UX guarantee that
# every container action is an `alfred` subcommand.
docker compose run --rm alfred-core migrate

step "Seeding state.git (idempotent)"
# devops-001: --entrypoint /bin/sh bypasses the `alfred` ENTRYPOINT so we
# can invoke the seed script directly. `alfred /app/bin/alfred-state-git-seed.sh`
# would land as an invalid alfred subcommand. The script (devops-009) is
# idempotent: re-running this step on a previously-seeded state.git is a
# no-op. spec §15.4 step 2.
docker compose run --rm --entrypoint /bin/sh alfred-core /app/bin/alfred-state-git-seed.sh

step "Priming secrets bind-mount"
# PR D2 devex-002: Compose silently creates a *directory* at the
# bind-mount host path if the host file is missing. That surfaces
# downstream as a confusing SecretBrokerPermissionsError because the
# secrets path inside the container is a directory, not a file. Touch
# the host file with `chmod 600` BEFORE any `docker compose up
# alfred-discord` so the bind-mount targets the right kind of inode.
secrets_dir="$HOME/.config/alfred"
secrets_file="$secrets_dir/secrets.toml"
mkdir -p "$secrets_dir"
chmod 700 "$secrets_dir"
if [[ ! -f "$secrets_file" ]]; then
  touch "$secrets_file"
  echo "Created empty secrets file at $secrets_file."
  echo "Edit it and add ``discord_bot_token = \"...\"`` before running 'alfred discord verify'."
fi
chmod 600 "$secrets_file"

# Export UID and GID so the compose `user: "${UID:-1000}:${GID:-1000}"`
# substitution picks up the operator's real uid/gid. macOS bash 3.2
# does NOT export UID by default, and GID is rarely exported on any
# shell. Without the explicit `export`, compose falls back to
# 1000:1000 which collides with the host operator on non-1000-uid
# systems and breaks the `chmod 600` enforcement on the bind-mount.
export UID
GID="$(id -g)"
export GID

step "Bootstrapping operator identity"
# Re-running this block is idempotent: the `--output-slug` flag makes
# `alfred user add` echo the canonical slug for downstream use without
# guessing in shell. The first invocation creates the operator; every
# subsequent run sees `has_operator=1` and skips.
user_list_json="$(docker compose run --rm alfred-core user list --json 2>/dev/null || true)"
if [[ -z "$user_list_json" ]]; then
  fail "user list failed (postgres reachable?)"
fi
has_operator="$(printf '%s' "$user_list_json" | jq -r '[.[] | select(.authorization=="operator")] | length')"
if [[ "$has_operator" == "0" ]]; then
  # Non-TTY guard: under CI / piped stdin we cannot prompt — fall back to
  # ALFRED_OPERATOR_NAME from .env (or the literal "Operator" if unset).
  if [[ ! -t 0 ]]; then
    name="${ALFRED_OPERATOR_NAME:-Operator}"
    echo "Non-TTY context: using ALFRED_OPERATOR_NAME='$name'."
  else
    read -r -p "Operator display name [Operator]: " name
    name="${name:-Operator}"
  fi
  budget="$(read_env_var ALFRED_DAILY_BUDGET_USD)"
  budget="${budget:-1.0}"
  # `--output-slug` echoes the canonical slug to stdout so we capture it
  # for the downstream slug-divergence note (the operator-typed display
  # name may transliterate / collide differently from a naive
  # lowercase).
  slug="$(docker compose run --rm alfred-core user add \
    --name "$name" \
    --authorization operator \
    --daily-budget-usd "$budget" \
    --output-slug 2>/dev/null)"
  slug="$(printf '%s' "$slug" | tr -d '[:space:]')"
  echo "Created operator user with slug '$slug'."
  # bash 3.2 portable lowercasing — never `${name,,}` (bash 4+ only).
  display_lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  if [[ "$slug" != "$display_lower" ]]; then
    echo "  (Slug differs from display-lowercase; use '$slug' in future CLI commands.)"
  fi
else
  echo "Operator user already exists; skipping create."
  slug="$(printf '%s' "$user_list_json" | jq -r '[.[] | select(.authorization=="operator")][0].slug')"
fi

# Optional Discord-bind prompt — TTY-only, skipped silently otherwise.
# A blank answer is the documented skip path. On non-empty input we
# bind the snowflake AND immediately run `alfred discord verify` so the
# operator gets a green/red signal before daemonising the long-running
# adapter.
if [[ -t 0 ]]; then
  step "Optional: bind a Discord snowflake"
  echo "  In Discord: Settings > Advanced > Developer Mode > right-click your user > Copy ID."
  read -r -p "Discord snowflake to bind now (blank to skip): " snowflake
  snowflake="$(printf '%s' "$snowflake" | tr -d '[:space:]')"
  if [[ -n "$snowflake" ]]; then
    docker compose run --rm alfred-core user bind \
      --slug "$slug" \
      --platform discord \
      --platform-id "$snowflake"
    echo "Bound snowflake $snowflake to operator $slug."
    if [[ -s "$secrets_file" ]] && grep -q '^discord_bot_token' "$secrets_file"; then
      step "Verifying Discord bot connectivity"
      if docker compose run --rm alfred-discord verify; then
        echo "Discord verify OK."
      else
        warn "Discord verify failed; inspect 'docker compose logs alfred-discord' or re-run."
      fi
    else
      echo "Skipping 'alfred discord verify' — set discord_bot_token in $secrets_file first."
    fi
  fi
fi

step "Setup complete"
echo "Run 'docker compose run --rm -it alfred-core chat' to open the TUI."
echo "Run 'docker compose up -d alfred-discord' to start the Discord adapter daemon."
