#!/usr/bin/env bash
# bin/alfred-plugin-launcher.sh — fail-closed plugin launcher (spec §4.8, §5.2).
#
# Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]
#
# Invariants enforced here (each one matters because the launcher is the
# sole path the supervisor uses to spawn plugins):
#
# 1. **Fail-closed.** Without a sandbox policy file
#    (${ALFRED_SANDBOX_POLICY_DIR}/<plugin_id>.policy), the launcher
#    refuses to exec the plugin. The ONLY escape hatch is the pair
#    ALFRED_ENV=development + ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1,
#    which prints a structured `supervisor.config_insecure` audit
#    JSON line on stderr before exec'ing. Production refuses the flag
#    unconditionally — sec-003.
#
# 2. **UID-drop on Linux.** `runuser -u "${TARGET_UID}" -- ...` runs
#    the plugin under a different uid so a compromised plugin cannot
#    read the parent process's secrets at the OS level. macOS dev has
#    no `runuser`; the launcher emits a
#    `launcher_uid_separation_unavailable_macos` audit JSON line and
#    execs without UID-drop. This is the documented Linux-only
#    deviation for Slice 3.
#
# 3. **Bare i18n keys on stderr.** No hardcoded English sentences —
#    the supervisor renders localised text from the audit row (i18n-005
#    option b). The catalog ships the key->message mapping; the
#    launcher only emits the key.
#
# 4. **`_do_exec` declared BEFORE the policy-file check.** CR R2 on
#    the PR-S3-0a plan caught a prior draft that invoked `_do_exec`
#    in the dev/unsandboxed branch before its function definition —
#    bash treats that as "command not found" and exits 127 silently on
#    that branch. Now the definition leads, the invocations follow.
#
# 5. **`set -eu` with no `pipefail`.** Matches the seed-script
#    convention from bin/alfred-state-git-seed.sh: the launcher has no
#    pipes, so `pipefail` would be cargo-culted. One convention to
#    learn for every shell script in this repo.

set -eu

PLUGIN_ID="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]}"
shift
EXECUTABLE="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]}"
shift

ALFRED_ENV="${ALFRED_ENV:-production}"
UNSANDBOXED="${ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED:-0}"
TARGET_UID="${ALFRED_PLUGIN_UID:-alfred-quarantine}"
SANDBOX_POLICY_DIR="${ALFRED_SANDBOX_POLICY_DIR:-/etc/alfred/sandbox}"
POLICY_FILE="${SANDBOX_POLICY_DIR}/${PLUGIN_ID}.policy"

# _do_exec runs the plugin process. Linux: UID-drop via runuser.
# macOS dev (no runuser): emit a supervisor.config_insecure audit
# JSON line on stderr and exec without UID-drop. The audit row is the
# operator's record that this deviation happened — the supervisor
# captures stderr and persists it as a real audit row.
#
# Defined here, BEFORE the policy-file check that calls it, so the
# dev/unsandboxed branch can invoke it without the bash "command not
# found" failure mode CR R2 flagged.
_do_exec() {
    if command -v runuser >/dev/null 2>&1; then
        exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}" "$@"
    else
        # macOS / non-Linux dev path. The audit JSON line is bare —
        # the supervisor parses it and renders localised text from
        # the catalog.
        printf '{"event":"supervisor.config_insecure","insecure_config_key":"launcher_uid_separation_unavailable_macos","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
        exec "${EXECUTABLE}" "$@"
    fi
}

# Production guard: UNSANDBOXED=1 is never accepted outside development.
# Bare i18n key on stderr (i18n-005 option b) — supervisor renders
# localised text from the catalog.
if [ "${ALFRED_ENV}" != "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
    printf 'plugin.launcher_no_sandbox_policy plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

# Policy-file check. Missing policy → refuse, unless dev + unsandboxed.
if [ ! -f "${POLICY_FILE}" ]; then
    if [ "${ALFRED_ENV}" = "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
        # Structured audit row on stderr (supervisor captures it).
        printf '{"event":"supervisor.config_insecure","insecure_config_key":"ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
        _do_exec "$@"
        exit 0
    fi
    printf 'plugin.launcher_no_sandbox_policy plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

_do_exec "$@"
