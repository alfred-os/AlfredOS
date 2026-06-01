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
#    unconditionally — sec-003. The production-refusal path uses a
#    distinct bare i18n key (`plugin.launcher_unsandboxed_rejected`)
#    so the audit row + operator-facing render can tell "unsandboxed
#    flag refused in prod" apart from "no sandbox policy file" — CR
#    on PR #140 caught the shared key as a real ambiguity.
#
# 2. **UID-drop on Linux — fail-closed when runuser is missing.** On
#    Linux, `runuser -u "${TARGET_UID}" -- ...` runs the plugin under
#    a different uid so a compromised plugin cannot read the parent
#    process's secrets at the OS level. On Linux WITHOUT `runuser`,
#    the launcher refuses (exit 1 + `plugin.launcher_uid_drop_unavailable`
#    bare key on stderr) rather than execing un-dropped — failing
#    open here would silently drop the security control this launcher
#    exists to enforce. CR on PR #140 caught the prior key-on-runuser
#    branching that mislabelled a no-runuser Linux box as the macOS
#    dev deviation. macOS / non-Linux dev has no `runuser`; the
#    launcher emits a `launcher_uid_separation_unavailable_macos`
#    audit JSON line and execs without UID-drop. This is the
#    documented macOS-only deviation for Slice 3.
#
# 3. **Bare i18n keys on stderr.** No hardcoded English sentences —
#    the supervisor renders localised text from the audit row (i18n-005
#    option b). The catalog ships the key->message mapping; the
#    launcher only emits the key.
#
# 4. **JSON audit rows are forensically safe.** PLUGIN_ID is validated
#    against a safe-charset regex (`[A-Za-z0-9._-]+`) at script entry
#    BEFORE any JSON-emitting branch runs. A plugin_id that fails the
#    check is refused with `plugin.launcher_plugin_id_invalid` and a
#    non-zero exit, so a malformed id (containing `"`, `\`, newlines,
#    etc.) can never reach a `printf` JSON template — CR on PR #140
#    flagged the unescaped interpolation as an audit-stream integrity
#    risk (PRD §5 + CLAUDE.md hard rule #7). The charset is intentionally
#    a strict subset of the upstream manifest parser's tolerance so the
#    launcher remains the last fail-closed gate even if upstream
#    validation drifts.
#
# 5. **`_do_exec` declared BEFORE the policy-file check.** CR R2 on
#    the PR-S3-0a plan caught a prior draft that invoked `_do_exec`
#    in the dev/unsandboxed branch before its function definition —
#    bash treats that as "command not found" and exits 127 silently on
#    that branch. Now the definition leads, the invocations follow.
#
# 6. **`set -eu` with no `pipefail`.** Matches the seed-script
#    convention from bin/alfred-state-git-seed.sh: the launcher has no
#    pipes, so `pipefail` would be cargo-culted. One convention to
#    learn for every shell script in this repo.

set -eu

# Help flag — must run BEFORE the charset validation so `--help` does not
# trip the unsafe-charset refusal. The help text is the operator-facing
# entry point; it documents the contract that the audit-row renderer
# elsewhere localises. Doc-string itself is operator-facing English; the
# launcher emits bare i18n keys only on the failure paths the supervisor
# captures and translates. DEVEX-005 fix.
case "${1:-}" in
    -h | --help)
        cat <<'HELP'
alfred-plugin-launcher.sh — fail-closed plugin launcher (spec §4.8, §5.2).

USAGE
    alfred-plugin-launcher.sh <plugin_id> <executable> [args...]

ARGS
    plugin_id    Manifest-declared plugin id. Charset [A-Za-z0-9._-]+; any
                 other character is refused (audit-stream integrity).
    executable   Absolute path to the plugin entrypoint. The launcher
                 exec's this after policy + UID-drop checks pass.
    args...      Forwarded to the plugin.

ENVIRONMENT
    ALFRED_ENV
        "development" enables the unsandboxed escape hatch (see
        ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED). Any other value (including
        empty) is treated as production: the launcher refuses to spawn
        without a sandbox policy file.

    ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED
        Dev-only escape hatch. With ALFRED_ENV=development AND this set
        to "1", the launcher spawns the plugin without a sandbox policy
        and emits a supervisor.config_insecure audit JSON line on stderr.
        Refused unconditionally outside development.

    ALFRED_SANDBOX_POLICY_DIR
        Directory containing per-plugin sandbox policy files. Default:
        /etc/alfred/sandbox. The launcher reads <DIR>/<plugin_id>.policy
        and refuses to spawn if the file is missing (production fail-
        closed).

    ALFRED_PLUGIN_UID
        Target UID for the runuser-based UID drop on Linux. Default:
        alfred-quarantine. Provision this account before deploying — the
        operator runbook at docs/runbooks/slice-3-plugins.md has the
        systemd-sysusers fragment.

EXIT CODES
    0    Success — exec'd the plugin (this process is replaced).
    1    Refusal — bare i18n key emitted on stderr. The supervisor
         captures stderr and renders the localised message from the
         catalog. Possible keys:
             plugin.launcher_plugin_id_invalid
             plugin.launcher_unsandboxed_rejected
             plugin.launcher_no_sandbox_policy
             plugin.launcher_uid_drop_unavailable

PLATFORM NOTES
    Linux        UID-drop via `runuser`. Refuses if runuser is absent.
    macOS / BSD  No runuser available; the launcher emits a
                 launcher_uid_separation_unavailable_macos audit JSON
                 line and exec's WITHOUT UID-drop (documented dev-only
                 deviation; not for production).

SEE ALSO
    docs/runbooks/slice-3-plugins.md   Operator runbook
    PRD §4.8, §5.2                     Spec for the launcher contract
HELP
        exit 0
        ;;
esac

PLUGIN_ID="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]  (try --help)}"
shift
EXECUTABLE="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]  (try --help)}"
shift

# Charset-validate PLUGIN_ID at the entry point so every downstream
# branch (including the JSON-emitting ones) can safely interpolate
# the value without a shell-escape step. The pattern matches the
# closed-vocabulary plugin slug shape from spec §5.6 and is a strict
# subset of what the upstream manifest parser accepts — the launcher
# is the last fail-closed gate, so it enforces the tighter contract.
case "${PLUGIN_ID}" in
    *[!A-Za-z0-9._-]* | "")
        # Bare i18n key + supervisor renders. The plugin_id is NOT
        # echoed here (a malformed id is exactly the thing we refuse
        # to round-trip into the audit stream).
        printf 'plugin.launcher_plugin_id_invalid\n' >&2
        exit 1
        ;;
esac

ALFRED_ENV="${ALFRED_ENV:-production}"
UNSANDBOXED="${ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED:-0}"
TARGET_UID="${ALFRED_PLUGIN_UID:-alfred-quarantine}"
SANDBOX_POLICY_DIR="${ALFRED_SANDBOX_POLICY_DIR:-/etc/alfred/sandbox}"
POLICY_FILE="${SANDBOX_POLICY_DIR}/${PLUGIN_ID}.policy"

# _do_exec runs the plugin process. Linux: UID-drop via runuser. If
# runuser is missing on Linux, REFUSE (fail-closed) rather than exec
# without UID separation — silently dropping the security control
# would violate the spec §4.8 / §5.2 invariant. Non-Linux (macOS dev):
# emit a supervisor.config_insecure audit JSON line on stderr and
# exec without UID-drop. The audit row is the operator's record that
# this deviation happened — the supervisor captures stderr and
# persists it as a real audit row.
#
# Defined here, BEFORE the policy-file check that calls it, so the
# dev/unsandboxed branch can invoke it without the bash "command not
# found" failure mode CR R2 flagged.
_do_exec() {
    if [ "$(uname -s)" = "Linux" ]; then
        if ! command -v runuser >/dev/null 2>&1; then
            # Linux without runuser — refuse rather than silently
            # exec without UID-drop. Bare i18n key on stderr; the
            # supervisor's renderer attaches the plugin_id from the
            # spawn context (the audit row schema carries it via the
            # supervisor's structured wrapper, not here).
            printf 'plugin.launcher_uid_drop_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
            exit 1
        fi
        exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}" "$@"
    else
        # macOS / non-Linux dev path. The audit JSON line is bare —
        # the supervisor parses it and renders localised text from
        # the catalog. PLUGIN_ID was charset-validated at script
        # entry so this interpolation cannot produce malformed JSON.
        printf '{"event":"supervisor.config_insecure","insecure_config_key":"launcher_uid_separation_unavailable_macos","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
        exec "${EXECUTABLE}" "$@"
    fi
}

# Production guard: UNSANDBOXED=1 is never accepted outside development.
# Bare i18n key on stderr (i18n-005 option b) — supervisor renders
# localised text from the catalog. Uses a distinct key from the
# "no policy file" refusal so audit/render can distinguish "operator
# tried to force unsandboxed in prod" from "policy file is missing"
# (CR on PR #140).
if [ "${ALFRED_ENV}" != "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
    printf 'plugin.launcher_unsandboxed_rejected plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

# Policy-file check. Missing policy → refuse, unless dev + unsandboxed.
if [ ! -f "${POLICY_FILE}" ]; then
    if [ "${ALFRED_ENV}" = "development" ] && [ "${UNSANDBOXED}" = "1" ]; then
        # Structured audit row on stderr (supervisor captures it).
        # PLUGIN_ID was charset-validated at script entry so this
        # interpolation cannot produce malformed JSON.
        printf '{"event":"supervisor.config_insecure","insecure_config_key":"ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED","plugin_id":"%s"}\n' "${PLUGIN_ID}" >&2
        _do_exec "$@"
        exit 0
    fi
    printf 'plugin.launcher_no_sandbox_policy plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

_do_exec "$@"
