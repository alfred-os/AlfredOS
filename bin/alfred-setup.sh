#!/usr/bin/env bash
# Idempotent setup script for AlfredOS Slice 1.
#
# Usage:
#   bin/alfred-setup.sh             # full setup
#   bin/alfred-setup.sh --dry-run   # check prerequisites only, then exit 0
#
# Safe to re-run any number of times: the .env copy is guarded by an
# existence check, `docker compose build` is a no-op when the cached
# layers are still valid, and `alfred migrate` is alembic-idempotent.
set -euo pipefail

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
fi

step() { printf "\n==> %s\n" "$1"; }
warn() { printf "WARNING: %s\n" "$1" >&2; }

step "Checking prerequisites"
command -v docker >/dev/null || { warn "docker not found"; exit 1; }
# `docker compose version` covers both the v2 subcommand and the
# `command -v docker compose` form (which doesn't actually work — kept
# as a defensive fallback for old setups).
command -v docker compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 \
  || { warn "docker compose not found"; exit 1; }

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

step "Setup complete"
echo "Run 'docker compose run --rm -it alfred-core chat' to open the TUI."
