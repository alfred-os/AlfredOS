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

step "Loading the bwrap userns AppArmor profile (#290)"
# The dual-LLM quarantine child runs under bubblewrap, which builds an
# unprivileged user namespace. On Ubuntu 24.04+ / kernel-6.x hosts with
# `kernel.apparmor_restrict_unprivileged_userns=1` (the modern default), the
# kernel refuses that namespace UNLESS the container process runs under an
# AppArmor profile carrying `userns,`. docker-compose.yaml points alfred-core at
# the custom `alfred-bwrap` profile via `security_opt`; that profile has to be
# loaded into the host kernel first. This is a one-time, root-requiring host
# step (apparmor_parser writes to the kernel). It is idempotent — re-running
# `apparmor_parser -r` replaces the profile in place.
#
# Skips GRACEFULLY where AppArmor is unavailable: macOS (no AppArmor at all) and
# SELinux/other-LSM Linux hosts have no `apparmor_parser`. There the
# `security_opt: apparmor=alfred-bwrap` line is ignored by the container runtime
# and the userns restriction this profile lifts is typically not present, so the
# spawn works without it. We WARN rather than fail so setup still completes.
APPARMOR_PROFILE="docker/apparmor/alfred-bwrap"
if command -v apparmor_parser >/dev/null 2>&1; then
  if [[ -f "$APPARMOR_PROFILE" ]]; then
    # Needs root to write the profile into the kernel. Use sudo only if we are
    # not already root, so the script works both as a normal user (prompts for
    # sudo) and under `sudo bin/alfred-setup.sh`.
    if [[ "$(id -u)" -eq 0 ]]; then
      apparmor_parser -r -W "$APPARMOR_PROFILE"
    else
      sudo apparmor_parser -r -W "$APPARMOR_PROFILE"
    fi
    echo "Loaded AppArmor profile 'alfred-bwrap' (grants userns for the bwrap quarantine child)."
  else
    warn "$APPARMOR_PROFILE not found — skipping AppArmor profile load. The dual-LLM quarantine child may fail to spawn on a userns-restricted host."
  fi
else
  warn "apparmor_parser not found (non-AppArmor host, e.g. macOS/SELinux). Skipping the userns AppArmor profile load — the security_opt line is a no-op on this host. If the dual-LLM quarantine child later fails to spawn with 'No permissions to create new namespace', this host needs a userns exemption."
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

step "Ensuring ~/.config/alfred/sandbox/ exists"
# Per-OS sandbox-policy files live here for PR-S4-6's launcher to
# resolve (spec §7.5–7.7). The directory is operator-controlled; this
# step only ensures it EXISTS with sensible default perms on first
# creation. Vendor or local policy files are dropped here by the
# operator (or shipped by downstream PR-S4-7 as default policies).
#
# DevEx closure (PR #215): chmod only on newly-created dirs. If the
# operator pre-created or symlinked ~/.config/alfred/sandbox to a
# shared location, leave the perms alone — operator intent wins. We
# warn (but do not refuse) on world-readable perms so the operator
# can see the trade-off.
sandbox_dir="$HOME/.config/alfred/sandbox"
if [[ ! -d "$sandbox_dir" ]]; then
  mkdir -p "$sandbox_dir"
  chmod 700 "$sandbox_dir"
  echo "Created $sandbox_dir (mode 0700)."
else
  current_mode="$(stat -c '%a' "$sandbox_dir" 2>/dev/null || stat -f '%A' "$sandbox_dir" 2>/dev/null || echo unknown)"
  if [[ "$current_mode" != "700" && "$current_mode" != "unknown" ]]; then
    echo "WARN: $sandbox_dir already exists with mode $current_mode (kept). "
    echo "      0700 is recommended; chmod yourself if you intend that."
  else
    echo "$sandbox_dir already exists; leaving alone."
  fi
fi

step "Bootstrapping audit.hash_pepper secret"
# AlfredOS uses audit.hash_pepper as the HMAC key for every *_hash
# audit-row field (PR-S4-5 operator_session.token_hash + machine_id_hash,
# PR-S4-8/9 platform_user_id_hash + verification_phrase_hash). Each
# purpose-specific subkey is HKDF-derived from this master pepper at
# the application layer (PR-S4-5 round-2 closure 3).
#
# This step is idempotent: if a non-empty value is already in the
# broker config file we leave it alone. Rotating the pepper
# invalidates cross-row correlation (spec §8.10), so the bootstrap
# MUST NOT clobber an existing value.
#
# Concurrency: the entire bootstrap (grep guard + append) runs inside
# a per-target-file lock acquired via mkdir (POSIX-portable; flock is
# Linux-only). Two concurrent setup-script invocations therefore see
# strict at-most-one bootstrap (PR #215 sec-2 closure — TOCTOU between
# grep and append).
#
# Key is written with TOML quoting (``"audit.hash_pepper" = ...``) so
# tomllib parses it as a top-level dotted string key rather than as a
# nested table ``{audit: {hash_pepper: ...}}`` (PR #215 cross-cutting
# closure — unquoted would have left SecretBroker.get(...) raising
# UnknownSecretError).
pepper_key="audit.hash_pepper"
target_file="${ALFRED_SECRETS_FILE:-$secrets_file}"
lock_dir="${target_file}.lock"

# PR #215 sec-1 closure: chmod 600 the target_file directly (the outer
# $secrets_file chmod only covered the default path).
_pepper_ensure_target() {
  if [[ ! -f "$target_file" ]]; then
    printf '# AlfredOS secrets file. DO NOT commit.\n' > "$target_file"
  fi
  chmod 600 "$target_file"
}

_pepper_bootstrap() {
  _pepper_ensure_target
  if grep -qE "^\"?${pepper_key}\"?[[:space:]]*=" "$target_file" 2>/dev/null; then
    echo "audit.hash_pepper already configured in ${target_file}; leaving alone."
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    cat >&2 <<EOF_NO_OPENSSL
ERROR: openssl is required to bootstrap audit.hash_pepper but is not on PATH.
       Install it for your distro and re-run this script (the run is
       idempotent — already-configured pepper is left alone):
         Debian/Ubuntu:   sudo apt-get install -y openssl
         Fedora/RHEL:     sudo dnf install -y openssl
         Arch:            sudo pacman -S openssl
         Alpine:          sudo apk add openssl
         macOS (brew):    brew install openssl
EOF_NO_OPENSSL
    return 1
  fi
  pepper_value="$(openssl rand -hex 32)"
  # Quote the dotted key so tomllib reads it as a flat string key
  # (cross-cutting BLOCKER closure).
  printf '"%s" = "%s"\n' "$pepper_key" "$pepper_value" >> "$target_file"
  echo "Seeded audit.hash_pepper into ${target_file}."
}

# mkdir-lock: POSIX atomic. Acquire, run, release.
if mkdir "$lock_dir" 2>/dev/null; then
  trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT INT TERM
  _pepper_bootstrap || _pepper_status=$?
  rmdir "$lock_dir"
  trap - EXIT INT TERM
  if [[ -n "${_pepper_status:-}" ]] && [[ "$_pepper_status" -ne 0 ]]; then
    exit "$_pepper_status"
  fi
else
  # Another concurrent setup invocation holds the lock. Wait up to 30
  # seconds for it to finish; if it never releases, refuse loudly
  # rather than racing.
  waited=0
  while [[ -d "$lock_dir" ]] && [[ "$waited" -lt 30 ]]; do
    sleep 1
    waited=$((waited + 1))
  done
  if [[ -d "$lock_dir" ]]; then
    echo "ERROR: audit.hash_pepper bootstrap lock ${lock_dir} held >30s — refusing to race." >&2
    exit 1
  fi
  # Lock released; the other invocation already bootstrapped (or
  # already-configured case). Just verify the key is present.
  if ! grep -qE "^\"?${pepper_key}\"?[[:space:]]*=" "$target_file" 2>/dev/null; then
    _pepper_bootstrap
  fi
fi

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
