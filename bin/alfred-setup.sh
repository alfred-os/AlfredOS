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
# `alfred gateway adapters --wait-ready discord` probe (#309).
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

# `openssl_missing_message WHAT` prints an actionable, per-distro install hint when a
# step that needs `openssl rand` finds openssl absent from PATH. Shared by both
# openssl-gated secret-seeding steps below (the Grafana admin password seed and the
# audit.hash_pepper bootstrap) so the guidance — and any future distro addition —
# lives in exactly one place instead of drifting between two near-identical heredocs.
openssl_missing_message() {
  local what="$1"
  cat >&2 <<EOF_NO_OPENSSL
ERROR: openssl is required to ${what} but is not on PATH.
       Install it for your distro and re-run this script (the run is
       idempotent — an already-configured secret is left alone):
         Debian/Ubuntu:   sudo apt-get install -y openssl
         Fedora/RHEL:     sudo dnf install -y openssl
         Arch:            sudo pacman -S openssl
         Alpine:          sudo apk add openssl
         macOS (brew):    brew install openssl
EOF_NO_OPENSSL
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

# #469 Blocker 2 Task 5: make the opt-in coherent. docker-compose.yaml now defaults
# ALFRED_GATEWAY_HOSTED_ADAPTERS to [] (Discord is opt-in), so setting a real Discord
# token alone no longer enables Discord — an operator's single action (the token) must
# still be the thing that flips the opt-in, or the "just set the token" quickstart story
# silently breaks. Idempotent (grep-guarded append-if-absent, like the other .env seeds
# in this script); preserves a deliberate `=[]` opt-out (operator intent wins); a
# commented/blank token already reads as empty via read_env_var, so it never re-arms the
# gateway's fail-closed missing-token crash-loop. Never echo the token itself.
seed_hosted_adapters() {
  local token; token="$(read_env_var ALFRED_DISCORD_BOT_TOKEN)"
  if [[ -n "$token" ]] && ! grep -qE '^ALFRED_GATEWAY_HOSTED_ADAPTERS=' .env; then
    # CodeRabbit finding 1 (#469 Blocker 2 PR review): a `.env` without a trailing
    # newline would otherwise glue the new key onto the last existing line — e.g.
    # `...real-tokenALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]` as ONE
    # unparseable line — so the new key is never grep-matchable and Discord silently
    # stays disabled. `tail -c1` reads the file's last byte; command substitution
    # strips a trailing newline from the result, so a non-empty result here means the
    # last byte on disk was NOT a newline. `-s .env` guards the fresh-empty-file case
    # (nothing to glue onto; a leading blank line there would be cosmetic noise).
    if [[ -s .env ]] && [[ -n "$(tail -c1 .env)" ]]; then
      printf '\n' >> .env
    fi
    printf '%s\n' 'ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]' >> .env
    echo "Discord token detected — enabled gateway-hosted Discord (ALFRED_GATEWAY_HOSTED_ADAPTERS in .env)."
  fi
}

# CodeRabbit finding 2 (#469 Blocker 2 PR review): the post-bind advisory must be based
# on the EFFECTIVE hosted-adapter set (i.e. what `.env` looks like AFTER
# seed_hosted_adapters has already run), not merely token presence. Under an explicit
# ALFRED_GATEWAY_HOSTED_ADAPTERS=[] opt-out, seed_hosted_adapters leaves operator intent
# alone even with a real token in .env — advertising the `--wait-ready discord` probe in
# that case would send the operator after an adapter that will never run. Factored into
# its own top-level function (mirrors seed_hosted_adapters) so it can be exercised
# directly by a real-execution test instead of only through the interactive,
# TTY-gated bind flow.
discord_probe_advisory() {
  local hosted; hosted="$(read_env_var ALFRED_GATEWAY_HOSTED_ADAPTERS)"
  if [[ "$hosted" == *alfred_discord* ]]; then
    echo "After 'docker compose up -d alfred-gateway', verify the Discord adapter with:"
    echo "  alfred gateway adapters --wait-ready discord"
  elif [[ -n "$(read_env_var ALFRED_DISCORD_BOT_TOKEN)" ]]; then
    # Token present but Discord is not in the effective hosted set — most likely a
    # deliberate ALFRED_GATEWAY_HOSTED_ADAPTERS=[] opt-out (operator intent wins per
    # seed_hosted_adapters). Don't advertise a probe for an adapter that won't run.
    warn "ALFRED_DISCORD_BOT_TOKEN is set but Discord is not in ALFRED_GATEWAY_HOSTED_ADAPTERS — it will not be gateway-hosted. To enable it: remove the ALFRED_GATEWAY_HOSTED_ADAPTERS=[] opt-out (or add \"alfred_discord\" to it) in .env, then 'docker compose up -d alfred-gateway'."
  else
    # devex-004: Discord is opt-in (docker-compose.yaml default is []). The seed step
    # above only flips ALFRED_GATEWAY_HOSTED_ADAPTERS when a token is present, so an
    # unset token here means it stayed empty on this run — point at both remedies.
    warn "ALFRED_DISCORD_BOT_TOKEN is unset. Discord is opt-in: set ALFRED_DISCORD_BOT_TOKEN in .env then re-run setup, or set ALFRED_GATEWAY_HOSTED_ADAPTERS manually (e.g. ALFRED_GATEWAY_HOSTED_ADAPTERS=[\"alfred_discord\"] in .env, NOT secrets.toml, which would shadow env) — then 'docker compose up -d alfred-gateway'."
  fi
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
    chmod 600 .env   # owner-only from creation — it will hold seeded/edited credentials
    echo "Created .env from .env.example. Edit it before running 'docker compose up'."
  else
    warn ".env.example not found; create .env manually."
  fi
fi
# Lock .env to owner-only on EVERY run — it holds the Grafana admin password (and other
# credentials) and must never be world-readable, whether freshly created, pre-existing, or
# ALREADY-seeded. Unconditional + before the seed write, so there is no disclosure window and
# an already-seeded but world-readable .env still gets locked (#470 security review).
[[ -f .env ]] && chmod 600 .env

step "Seeding opt-in Discord hosted-adapter set"
# Top-level — NOT inside the `[[ -t 0 ]]` interactive-snowflake branch further down. This
# must run on every invocation (TTY or not, whether or not the operator ever binds a
# snowflake) so a non-interactive/CI/first-run `bin/alfred-setup.sh` still honours a
# token already present in .env. Placed before the credential-validation gate below
# (which `exit 1`s on a missing DeepSeek/quarantine key) so the seed still runs even on
# a first pass where those other keys are not yet set.
seed_hosted_adapters

step "Seeding Grafana admin password"
# #470 PR2 Task 3 (rev.4 devops-003/devops-004/sec-004/sec-005): guard on
# PRESENT-AND-NON-EMPTY, not absent. .env.example ships
# GF_SECURITY_ADMIN_PASSWORD= (empty), and the step above does
# `cp .env.example .env` on first run, so the key is PRESENT but EMPTY — an
# "if absent, append" guard would never fire and Grafana would boot with an
# empty admin password (sec-004). Placement is load-bearing: AFTER
# `cp .env.example .env` creates the file, BEFORE the credential-validation
# gate below, so a stock first run seeds in one pass.
#
# This seed is genuinely different from the audit.hash_pepper bootstrap
# further down (.env, not secrets.toml; present-and-non-empty, not
# present-only; in-place `sed`, not append) — mirroring that seed literally
# would reproduce the wrong guard shape here. A concurrency lock is
# optional: the docker-compose.yaml entrypoint preflight guard is the
# fail-closed backstop for any weak/empty result regardless of a lost race.
if ! grep -qE '^GF_SECURITY_ADMIN_PASSWORD=.+' .env; then
  # (.env is already 0600 from the unconditional lock above, before this write.)
  # Graceful openssl preflight — a bare `openssl rand` under `set -euo
  # pipefail` aborts opaquely on a host without openssl. Shares its message
  # with the audit.hash_pepper bootstrap below via openssl_missing_message.
  if ! command -v openssl >/dev/null 2>&1; then
    openssl_missing_message "generate GF_SECURITY_ADMIN_PASSWORD"
    exit 1
  fi
  pw="$(openssl rand -hex 24)"
  # Write under `umask 077` so sed's backup/temp files are also owner-only (the in-place
  # .env keeps its 600 mode). Replace an existing empty line (the cp shape), else append.
  if grep -qE '^GF_SECURITY_ADMIN_PASSWORD=' .env; then
    ( umask 077 && sed -i.bak "s|^GF_SECURITY_ADMIN_PASSWORD=.*|GF_SECURITY_ADMIN_PASSWORD=${pw}|" .env ) && rm -f .env.bak
  else
    ( umask 077 && printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$pw" >> .env )
  fi
  echo "Seeded GF_SECURITY_ADMIN_PASSWORD into .env."
fi

step "Validating .env credentials"
# ---------------------------------------------------------------------------
# ONE gate for every credential the stack needs, reporting ALL problems at once.
#
# This used to be two checks in two places, each with its own immediate `exit 1`,
# and the ordering made the second one DEAD on the path that matters most. A
# stock first run is `cp .env.example .env`, which ships the literal `sk-...`
# DeepSeek placeholder AND an empty ALFRED_QUARANTINE_PROVIDER_API_KEY. The
# DeepSeek placeholder check exited first, so the quarantine-key warning added
# when a keyless stack became a REFUSE-BOOT was never reached on the very run it
# was written for: the operator fixed the DeepSeek key, re-ran, and only then
# discovered the second required key. Accumulating means one report, one fix pass.
#
# Deliberately NOT `source .env`. Sourcing executes the file as bash, which means
# `#` truncates lines silently, `$()` runs subshells, and an operator-pasted line
# can run arbitrary commands. `read_env_var` uses a grep|cut|tr pipeline instead;
# its `tr -d` strips surrounding quotes so `ALFRED_DEEPSEEK_API_KEY="sk-..."` is
# treated the same as the bare form.
#
# A newline-delimited string, NOT a bash array: macOS ships bash 3.2, where
# `${#arr[@]}` on an empty array trips `set -u` ("unbound variable"). The script
# already accommodates 3.2 elsewhere (see the UID/GID export below).
# ---------------------------------------------------------------------------
config_problems=""
add_config_problem() { config_problems="${config_problems}  - ${1}"$'\n'; }

deepseek_key="$(read_env_var ALFRED_DEEPSEEK_API_KEY)"
if [[ -z "$deepseek_key" ]]; then
  add_config_problem "ALFRED_DEEPSEEK_API_KEY is empty in .env. Set a DeepSeek API key from https://platform.deepseek.com."
elif [[ "$deepseek_key" == "sk-..." ]]; then
  # Reject the literal placeholder shipped in .env.example. Catching it here
  # (rather than letting it propagate to the provider call) gives operators a
  # friendly error before the container even boots. The settings.py validator
  # enforces the same invariant inside the app for any path that skips this script.
  add_config_problem "ALFRED_DEEPSEEK_API_KEY is still the literal 'sk-...' placeholder from .env.example. Replace it with a real DeepSeek API key from https://platform.deepseek.com."
fi

# #587: ALFRED_QUARANTINE_PROVIDER selects WHICH provider the quarantine child dials, and
# is a CLOSED SET — Settings.quarantine_provider is Literal["anthropic", "deepseek"], with
# no case/whitespace normalisation, so `Anthropic`, `openai`, or a stray-quoted value fails
# pydantic validation and the core exits on the audited settings_invalid boot path. Until
# this check existed the script validated the quarantine KEY while being entirely blind to
# the setting that decides which key is even correct — so a typo here sailed through setup
# and surfaced as a crash-loop.
#
# Shell env first, then .env: docker compose gives the shell environment precedence over
# .env (the same precedence the quarantine-key branch below documents), so checking .env
# alone would validate a value the stack will not actually use. Unset is FINE — Settings
# defaults to "anthropic" — so only a set-but-out-of-set value is a problem.
#
# `${VAR+x}`, NOT `${VAR:-...}` (CodeRabbit r2). `:-` fires on unset AND on set-but-empty,
# which collapses two cases docker compose keeps distinct: `ALFRED_QUARANTINE_PROVIDER:
# ${ALFRED_QUARANTINE_PROVIDER:-anthropic}` in docker-compose.yaml means an EXPLICITLY
# EMPTY shell var still wins over `.env` and lands the container on the "anthropic"
# default. Under `:-` this script instead fell through and validated the `.env` value —
# a value the stack would not use — so an operator with `ALFRED_QUARANTINE_PROVIDER=""`
# exported and `ALFRED_QUARANTINE_PROVIDER=deepseek` in `.env` got the wrong answer from
# setup. `+x` tests SET-NESS only, so the two cases stay apart.
#
# The `anthropic`/`deepseek` literals below are a hand-maintained copy of this closed
# set (the six Python copies — Settings.quarantine_provider / primary_provider /
# fallback_provider's Literals, the CLI validator, the proposal-payload validator, and
# the quarantine child's own `__main__._SUPPORTED_PROVIDER_IDS` — are pinned against
# each other by tests/unit/config/test_settings.py::
#   TestQuarantineProviderSettings::test_provider_closed_set_copies_stay_in_lockstep).
# Bash cannot import that frozenset, and deriving it would cost far more than a 2-value
# list is worth, so this comment is the link: WIDENING THE CLOSED SET FOR A NEW PROVIDER
# MUST UPDATE THIS BRANCH TOO — that Python test will not fail for you if you forget.
if [[ -n "${ALFRED_QUARANTINE_PROVIDER+x}" ]]; then
  quarantine_provider="${ALFRED_QUARANTINE_PROVIDER:-anthropic}"
  quarantine_provider_source="your shell environment — docker compose prefers this over .env"
else
  quarantine_provider="$(read_env_var ALFRED_QUARANTINE_PROVIDER)"
  quarantine_provider_source=".env"
fi
if [[ -n "$quarantine_provider" ]] &&
   [[ "$quarantine_provider" != "anthropic" && "$quarantine_provider" != "deepseek" ]]; then
  # The offending value is deliberately NOT reprinted (CodeRabbit): ALFRED_QUARANTINE_
  # PROVIDER_API_KEY sits directly beside this variable in .env, and a credential pasted
  # onto the wrong line must not be copied into setup output, shell scrollback, or a CI
  # log. Naming the SOURCE instead recovers the diagnostic value the echo was carrying —
  # the operator's real confusion in a shell-vs-.env precedence case is which file they're
  # editing, not what they typed (they can already see that). ${quarantine_provider_source}
  # is a script-authored literal, structurally incapable of carrying operator input — the
  # bash analogue of alfred.cli._settings_errors' field-path-only rendering.
  add_config_problem "ALFRED_QUARANTINE_PROVIDER (read from ${quarantine_provider_source}) is set to an unsupported value. It must be exactly 'anthropic' or 'deepseek' (lowercase, no quotes) — or left unset to use the 'anthropic' default. Any other value refuses boot on the settings_invalid path. See .env.example and docs/runbooks/slice-3-quarantined-llm.md."
fi

# #586: ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION is an opt-in REFUSE-BOOT posture,
# newly forwarded to alfred-core by this same PR, and this gate was blind to it. An
# operator following the README's advice to enable the strict posture, while running one
# provider for both roles, passed setup CLEANLY and then met exit 2
# (quarantine_provider_separation_violated) on the first `docker compose up -d` — a
# crash-loop under `restart: unless-stopped`, exactly the fix-one-thing/re-run/discover-
# the-next-problem friction this gate exists to eliminate.
#
# HARD FAILURE, not a warning: setup-time severity mirrors the boot-time consequence.
# require=true + collision REFUSES (exit 2, audited daemon.boot.failed row); the
# require=false default only WARNS and boots (_comms_boot.py's not-enforced arm) — which
# is why this is gated on resolved truthiness, not on same-provider alone.
#
# WHICH PRIMARY PROVIDER — deliberately NOT `read_env_var ALFRED_PRIMARY_PROVIDER`.
# docker-compose.yaml does not list ALFRED_PRIMARY_PROVIDER in alfred-core's
# `environment:` block, declares no `env_file:`, and bind-mounts no `.env` (the service
# mounts only alfred_state_git + alfred_run) — so under the deployment THIS SCRIPT SETS
# UP, Settings.primary_provider ALWAYS resolves to its "deepseek" default whatever the
# shell or .env say (see .env.example's ALFRED_PRIMARY_PROVIDER block; #590 tracks wiring
# the field up). Reading .env here would be wrong in BOTH directions: it would PASS
# PRIMARY=anthropic + QUARANTINE=deepseek (which crash-loops — the container compares
# deepseek vs deepseek) and FAIL PRIMARY=anthropic + QUARANTINE=anthropic (which boots
# fine). The gate must model the value the STACK will use, not the value the operator
# happened to write down for a host-side `alfred` invocation.
# COUPLING: if docker-compose.yaml ever forwards ALFRED_PRIMARY_PROVIDER, this constant
# MUST become the same ${VAR+x} resolution used above, or this gate silently certifies
# the wrong pair —
# tests/unit/test_compose_invariants.py::test_primary_and_fallback_provider_are_not_forwarded_to_core
# is the mechanical pin that would need to flip alongside it.
compose_primary_provider="deepseek"

if [[ -n "${ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION+x}" ]]; then
  require_separation="${ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION:-false}"
else
  require_separation="$(read_env_var ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION)"
fi

# quarantine_provider_norm: normalise as provider_ids_collide() does (.strip().lower())
# — belt-and-braces: a mis-cased ALFRED_QUARANTINE_PROVIDER already fails the closed-set
# branch above (that check runs against the RAW, un-normalised value, so a whitespace- or
# case- mangled value is already flagged there), so an operator whose value is BOTH
# mis-cased and colliding learns both problems in one setup run instead of
# fix-case / re-run / discover-collision. Stripping here is redundant-but-harmless with
# that earlier gate, never the ONLY check. tr, not bash 4+ ${var,,}: this script targets
# bash 3.2 (macOS system bash).
#
# require_separation_norm: case-fold ONLY — do NOT strip whitespace (round-6 review
# fleet / CodeRabbit). Unlike quarantine_provider, require_separation has no earlier
# raw-value gate, so stripping whitespace here would be the ONLY check, and it would
# silently PASS a value pydantic's bool parser REJECTS: that parser is a CLOSED SET,
# case-insensitive, with NO whitespace tolerance (true/1/yes/y/on/t,
# false/0/no/off/f/n — anything else, including a whitespace-padded value, raises
# settings_invalid). A stripped " true" would match the true-branch below and read as
# "no problem" while the real daemon refuses to boot — the exact silent-miss this gate
# exists to prevent. Case-folding alone is safe: pydantic's bool parser IS
# case-insensitive, so folding case never turns a real rejection into a false accept.
require_separation_norm="$(printf '%s' "$require_separation" | tr '[:upper:]' '[:lower:]')"
quarantine_provider_norm="$(printf '%s' "$quarantine_provider" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
quarantine_provider_effective="${quarantine_provider_norm:-anthropic}"

case "$require_separation_norm" in
  true | 1 | yes | y | on | t)
    if [[ "$quarantine_provider_effective" == "$compose_primary_provider" ]]; then
      add_config_problem "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION is enabled, but the quarantine and privileged providers are both '${compose_primary_provider}'. 'docker compose up -d' WILL REFUSE TO BOOT (exit 2, quarantine_provider_separation_violated) and crash-loop under 'restart: unless-stopped'. Set ALFRED_QUARANTINE_PROVIDER to the other provider (and a matching key in ALFRED_QUARANTINE_PROVIDER_API_KEY), or set ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=false for the default warn-only posture. NOTE: the privileged side is fixed at '${compose_primary_provider}' under docker compose — ALFRED_PRIMARY_PROVIDER is NOT forwarded and cannot change this. See docs/adr/0064-quarantine-provider-separation-is-opt-in.md and issue #590."
    fi
    ;;
  "" | false | 0 | no | off | f | n) ;;
  *)
    # The offending value is deliberately NOT reprinted (same rationale as the
    # ALFRED_QUARANTINE_PROVIDER diagnostic above): this field sits in the same .env
    # neighbourhood as ALFRED_QUARANTINE_PROVIDER_API_KEY, and an operator who fat-
    # fingered a credential onto the wrong line must not have it echoed into setup
    # output, shell scrollback, or a CI log.
    add_config_problem "ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION is set to an unsupported boolean value. It must be one of true/1/yes/y/on/t or false/0/no/off/f/n (any case) — or left unset for the 'false' default. Any other value (including a whitespace-padded one) refuses boot on the settings_invalid path."
    ;;
esac

# #340 PR2b-golive: the quarantined (dual-LLM) child now makes REAL provider calls, so
# ALFRED_QUARANTINE_PROVIDER_API_KEY became a hard boot requirement — the core resolves
# it pre-spawn and exits 2 with `quarantine_provider_key_unset` when unset.
#
# Unlike audit.hash_pepper this CANNOT be auto-seeded (only the operator has a provider
# credential) and, unlike the Discord token, it cannot be skipped by disabling a feature:
# it gates the whole comms boot. Catch it here rather than let `docker compose up -d`
# crash-loop under `restart: unless-stopped`.
#
# alfred-core mounts no secrets.toml, so `.env` + compose env forwarding is the ONLY
# route for this key — there is no secrets-file alternative to offer.
quarantine_key="$(read_env_var ALFRED_QUARANTINE_PROVIDER_API_KEY)"
if [[ -n "$quarantine_key" ]]; then
  echo "ALFRED_QUARANTINE_PROVIDER_API_KEY is configured in .env."
elif [[ -n "${ALFRED_QUARANTINE_PROVIDER_API_KEY:-}" ]]; then
  # NOT a failure. `docker compose` gives the SHELL environment precedence over `.env`
  # (verified: with `FOO=from_dotenv` in .env, `FOO=from_shell docker compose config`
  # renders `from_shell`). This stack boots fine. The earlier text here claimed the
  # opposite — "docker compose reads .env, so the stack will still refuse to boot" —
  # and sent an operator whose setup was already working off to debug it. The real
  # (and much smaller) caveat is durability, so say only that.
  echo "NOTE: ALFRED_QUARANTINE_PROVIDER_API_KEY is set in your shell but not in .env."
  echo "      That works — docker compose gives the shell environment precedence over"
  echo "      .env — but only for compose commands run from a shell that exports it."
  echo "      Add it to .env to make it durable across terminals."
else
  add_config_problem "ALFRED_QUARANTINE_PROVIDER_API_KEY is unset. 'docker compose up -d' WILL REFUSE TO BOOT (exit 2, quarantine_provider_key_unset) and crash-loop. This key is the quarantined half of the dual-LLM split; it is required, not optional. Set it in .env (see .env.example) — alfred-core mounts no secrets.toml, so .env is the only route."
fi

if [[ -n "$config_problems" ]]; then
  printf 'ERROR: .env is not ready — %s\n' "fix all of the following, then re-run bin/alfred-setup.sh:" >&2
  printf '%s' "$config_problems" >&2
  printf 'Nothing was changed. The stack was NOT started.\n' >&2
  exit 1
fi
echo ".env credentials OK."

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
    # This host HAS AppArmor (apparmor_parser is present) but the profile file is
    # absent from the checkout. That is a build-integrity error, NOT a
    # graceful-skip case: docker-compose.yaml pins alfred-core at
    # `security_opt: apparmor=alfred-bwrap`, so Docker will REFUSE to create the
    # container against an unloaded profile and the stack will not boot. Fail
    # loud rather than warn-and-continue into a confusing later failure.
    fail "$APPARMOR_PROFILE not found, but this host has AppArmor (apparmor_parser present). The compose file requires this profile (security_opt: apparmor=alfred-bwrap) — restore it from the repo and re-run. Without it alfred-core will not start on this host."
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
# alfred-gateway` so the bind-mount targets the right kind of inode.
secrets_dir="$HOME/.config/alfred"
secrets_file="$secrets_dir/secrets.toml"
mkdir -p "$secrets_dir"
chmod 700 "$secrets_dir"
if [[ ! -f "$secrets_file" ]]; then
  touch "$secrets_file"
  echo "Created empty secrets file at $secrets_file."
  echo "NOTE: secrets.toml is for broker-managed secrets (hash pepper, provider API keys, etc.)."
  echo "      The Discord bot token is now ALFRED_DISCORD_BOT_TOKEN in .env (not secrets.toml)."
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
    openssl_missing_message "bootstrap audit.hash_pepper"
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

# NOTE: the quarantined-LLM provider-key check used to live here. It moved UP into the
# "Validating .env credentials" gate near the top of this script — down here it sat
# behind the DeepSeek placeholder check's `exit 1`, so on a stock first run (a verbatim
# `cp .env.example .env`) it was never reached at all.

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
# bind the snowflake AND run `alfred gateway adapters --wait-ready discord`
# so the operator gets a green/red signal before daemonising (#309).
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
    # #309 preflight: gateway-hosted Discord needs the token core-side, or the gateway
    # ABORTS at first spawn (loud + audited, but it takes the relay down — #331). Refuse
    # to bring Discord up without it rather than ship a green stack with a dead bot.
    if grep -qE '^[[:space:]]*alfred-discord:' docker-compose.yaml 2>/dev/null; then
      warn "Legacy alfred-discord Compose service detected — removed in the #309 flag-day. Pull latest docker-compose.yaml. See docs/runbooks/2026-06-25-discord-flag-day-migration.md."
    fi
    # #514: `docker compose ps … | grep -qx` SIGPIPEs the producer under `pipefail` once the
    # service list outgrows the pipe buffer. Read into a var, then match with no pipeline.
    _services="$(docker compose ps --services 2>/dev/null || true)"
    if grep -qx alfred-discord <<<"$_services"; then
      warn "A stale alfred-discord container is running — 'docker compose down' then 'up -d'."
    fi
    # CodeRabbit finding 2 (#469 Blocker 2 PR review): base the advisory on the
    # EFFECTIVE hosted-adapter set (discord_probe_advisory, defined above), not merely
    # token presence — under an explicit ALFRED_GATEWAY_HOSTED_ADAPTERS=[] opt-out
    # Discord is NOT gateway-hosted even with a real token in .env, and the old
    # token-only check advertised a --wait-ready probe for an adapter that would
    # never run.
    discord_probe_advisory
  fi
fi

step "Setup complete"
echo "Run 'docker compose up -d' to start the long-running alfred-core daemon + gateway."
# 'chat' dials the always-up gateway over the shared alfred_run socket volume, so the
# one-off container links into the running stack (gateway holds the session across a
# core restart). 'run --rm' overrides the service's 'daemon start' command.
echo "Run 'docker compose run --rm -it alfred-core chat' to open the TUI (via the gateway)."
echo "Run 'docker compose up -d alfred-gateway' to start the gateway (hosts the Discord adapter)."
