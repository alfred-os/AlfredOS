#!/usr/bin/env bash
# bin/alfred-plugin-launcher.sh — fail-closed plugin launcher.
#
# Slice-3 (spec §4.8, §5.2) shipped the UID-separated baseline: charset-
# validate PLUGIN_ID, refuse without a sandbox posture, UID-drop via runuser
# on Linux. PR-S4-6 (spec §7) extends it with a manifest-driven, policy-
# resolving flow while preserving every Slice-3 invariant:
#
#   1. **--self-test** returns the policy-resolving signature so the daemon
#      boot probe (PR-S4-1) knows the launcher genuinely sandboxes.
#   2. **Settings.environment** is read via the pre-launcher Python helper
#      (manifest_reader --read-environment): ALFRED_ENVIRONMENT env var >
#      /etc/alfred/environment file. Neither set → refuse.
#   3. **Dev escape hatch refuses in production.** ALFRED_PLUGIN_LAUNCHER_-
#      UNSANDBOXED=1 + environment=production → refuse with an operator-
#      visible stderr key + a SANDBOX_REFUSED audit JSON row.
#   4. **Manifest [sandbox] block** drives the branch:
#        kind:full → resolve per-OS policy_ref (path-confined in Python),
#                    translate to bwrap flags, exec bwrap --sync-fd 3.
#        kind:none → Slice-3 UID-separated runuser path (unchanged).
#        kind:stub → refuse in production; dev emits a stub-used audit row.
#
# Invariants that DO NOT change from Slice-3:
#   * Fail-closed everywhere; bare i18n keys on stderr (the supervisor
#     renders localised text from the catalog — i18n-005 option b).
#   * PLUGIN_ID is charset-validated ([A-Za-z0-9._-]+) BEFORE any JSON-
#     emitting branch so a malformed id can never reach a printf JSON
#     template (audit-stream integrity — CR on PR #140).
#   * _do_exec is defined BEFORE any call site (CR R2 on PR-S3-0a).
#   * set -eu, no pipefail (the launcher has no pipes; matches the
#     seed-script convention).
#
# sec-1 (PR #205 round-2): the truthy helper below matches the Python helper
# in src/alfred/cli/daemon/_daemon_probes.py (accepted: 1/true/yes/on,
# case-insensitive, whitespace-trimmed). NEVER [ "$VAR" = "1" ].

set -eu

# --self-test — the daemon boot probe (PR-S4-1) shells out to this and only a
# REAL policy-resolving launcher returns the policy-resolving signature. Must
# run BEFORE positional-arg parsing so the probe needs no plugin args.
case "${1:-}" in
    --self-test)
        printf 'policy-resolving\n'
        exit 0
        ;;
esac

# Help flag — BEFORE charset validation so --help does not trip the unsafe-
# charset refusal. Operator-facing English; the launcher emits bare i18n
# keys only on the failure paths the supervisor captures and translates.
case "${1:-}" in
    -h | --help)
        cat <<'HELP'
alfred-plugin-launcher.sh — fail-closed plugin launcher (spec §4.8, §5.2, §7).

USAGE
    alfred-plugin-launcher.sh <plugin_id> <executable> [args...]
    alfred-plugin-launcher.sh --self-test
    alfred-plugin-launcher.sh --help

ARGS
    plugin_id    Manifest-declared plugin id. Charset [A-Za-z0-9._-]+; any
                 other character is refused (audit-stream integrity).
    executable   Absolute path to the plugin entrypoint. The launcher
                 exec's this after policy + UID-drop checks pass.
    args...      Forwarded to the plugin.

ENVIRONMENT
    ALFRED_ENVIRONMENT
        development | production | test. Read via the pre-launcher Python
        helper (env var > /etc/alfred/environment file). Mandatory — the
        launcher refuses to spawn when neither source resolves.

    ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED
        Dev-only escape hatch. Truthy (1/true/yes/on) in development spawns
        the plugin without resolving a policy. Refused in production with a
        SANDBOX_REFUSED audit row.

    ALFRED_SANDBOX_POLICY_DIR
        Override the sandbox-policy root for policy_ref confinement.

    ALFRED_PLUGIN_MANIFEST_PATH
        Test override: read the manifest from this path instead of resolving
        it from the plugin-id.

    ALFRED_PLUGIN_UID
        Target UID for the runuser UID drop on Linux (kind:none). Default:
        alfred-quarantine.

    FAKE_UNAME
        Test override for the host-OS detection (Darwin / Linux / Windows_NT).
        IGNORED in production — the launcher always uses the real `uname -s`
        there, and a FAKE_UNAME set in production is a loud SANDBOX_REFUSED
        refusal (it can only be an attempt to force a host-OS branch).

EXIT CODES
    0    Success — exec'd the plugin (this process is replaced).
    1    Refusal — bare i18n key + (where applicable) a SANDBOX_REFUSED audit
         JSON row on stderr.

SEE ALSO
    docs/runbooks/slice-3-plugins.md   Operator runbook
    PRD §4.8, §5.2 · spec §7           Launcher contract
HELP
        exit 0
        ;;
esac

PLUGIN_ID="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]  (try --help)}"
shift
EXECUTABLE="${1:?Usage: alfred-plugin-launcher.sh <plugin_id> <executable> [args...]  (try --help)}"
shift

# Charset-validate PLUGIN_ID at entry so every downstream branch (including
# the JSON-emitting ones) can safely interpolate it. The pattern is a strict
# subset of the upstream manifest parser's tolerance — the launcher is the
# last fail-closed gate.
case "${PLUGIN_ID}" in
    *[!A-Za-z0-9._-]* | "")
        printf 'plugin.launcher_plugin_id_invalid\n' >&2
        exit 1
        ;;
esac

# sec-1: shared truthy helper. Matches src/alfred/cli/daemon/_daemon_probes.py
# (_truthy_env) — accepted values 1/true/yes/on, case-insensitive. POSIX
# whitespace-trim BEFORE the case-match. NEVER [ "$VAR" = "1" ].
_truthy() {
    _t_val="${1:-}"
    # Trim leading + trailing whitespace (POSIX parameter expansion).
    _t_val="${_t_val#"${_t_val%%[![:space:]]*}"}"
    _t_val="${_t_val%"${_t_val##*[![:space:]]}"}"
    case "$(printf '%s' "${_t_val}" | tr '[:upper:]' '[:lower:]')" in
        1 | true | yes | on) return 0 ;;
        *) return 1 ;;
    esac
}

# Read Settings.environment via the pre-launcher Python helper (dual-source:
# ALFRED_ENVIRONMENT env var > /etc/alfred/environment). Neither set → refuse.
# The helper prints the value on stdout and a bare i18n key on stderr.
#
# sec-keystone (CR PR #229 finding-1): the environment is resolved BEFORE host-
# OS detection so the FAKE_UNAME shim can be gated to non-production. An
# attacker who controls the launcher env on a production Linux host must NOT be
# able to force the non-Linux branch (which historically exec'd unsandboxed) by
# setting FAKE_UNAME=Darwin. The helper's stderr (the specific i18n key) is
# captured (low-3) so the launcher surfaces the precise refusal reason —
# environment_not_set vs environment_unrecognised — not a generic one.
_ENV_ERR_FILE="$(mktemp "${TMPDIR:-/tmp}/alfred-launcher-env-err.XXXXXX")"
if ! ALFRED_RESOLVED_ENVIRONMENT="$(python3 -m alfred.plugins.manifest_reader --read-environment 2>"${_ENV_ERR_FILE}")"; then
    # The helper emits a closed-vocabulary bare key (daemon.boot.environment_-
    # not_set | daemon.boot.environment_unrecognised) on its LAST stderr line.
    # Surface it verbatim (low-3) instead of discarding it with 2>/dev/null and
    # refusing with a generic reason; fall back to the not_set key if the
    # capture was empty (fail-closed).
    _env_err_key="$(tail -n 1 "${_ENV_ERR_FILE}" 2>/dev/null || true)"
    rm -f "${_ENV_ERR_FILE}"
    case "${_env_err_key}" in
        daemon.boot.environment_unrecognised | daemon.boot.environment_not_set) : ;;
        *) _env_err_key="daemon.boot.environment_not_set" ;;
    esac
    printf '%s plugin_id=%s\n' "${_env_err_key}" "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"%s","environment":"unset","host_os":"unknown"}\n' "${PLUGIN_ID}" "${_env_err_key#daemon.boot.}" >&2
    exit 1
fi
rm -f "${_ENV_ERR_FILE}"

IS_PRODUCTION=false
[ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ] && IS_PRODUCTION=true

# _uname shim — honours FAKE_UNAME for the cross-OS CI matrix (devops-2) so the
# macOS and Windows branches can be exercised on Linux runners. sec-keystone:
# FAKE_UNAME is a TEST override only — it is IGNORED in production so a
# production host always reports its REAL kernel (`uname -s`). A FAKE_UNAME set
# in production is a loud refusal below (it can only be an attempt to force the
# non-Linux/unsandboxed branch on a Linux host).
_uname() {
    if [ "${IS_PRODUCTION}" = "false" ] && [ -n "${FAKE_UNAME:-}" ]; then
        printf '%s' "${FAKE_UNAME}"
    else
        uname -s
    fi
}

# Normalise the host OS to {linux, macos, windows}.
_host_os() {
    case "$(_uname | tr '[:upper:]' '[:lower:]')" in
        linux) printf 'linux' ;;
        darwin) printf 'macos' ;;
        mingw* | msys* | cygwin* | windows_nt) printf 'windows' ;;
        *) printf 'unknown' ;;
    esac
}

# sec-keystone: a FAKE_UNAME set in production is a hard refusal. It cannot
# serve any legitimate purpose (the shim is ignored above) and its presence on
# a production launcher invocation is an attempt to force a host-OS branch.
# Refuse loudly with a sandbox_refused row BEFORE any host-OS branch runs.
if [ "${IS_PRODUCTION}" = "true" ] && [ -n "${FAKE_UNAME:-}" ]; then
    printf 'supervisor.sandbox.refused.fake_uname_in_production plugin_id=%s\n' "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"fake_uname_in_production","environment":"production","host_os":"linux"}\n' "${PLUGIN_ID}" >&2
    exit 1
fi

UNSANDBOXED="${ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED:-}"
TARGET_UID="${ALFRED_PLUGIN_UID:-alfred-quarantine}"
HOST_OS="$(_host_os)"

if [ "${HOST_OS}" = "unknown" ]; then
    printf 'supervisor.sandbox.refused.unknown_host_os plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

# _do_exec runs the plugin process under the Slice-3 UID-separated baseline
# (kind:none). Linux: UID-drop via runuser; refuse if runuser missing (fail-
# closed). Non-Linux: a genuine macOS/Windows host (or a dev FAKE_UNAME shim)
# has no UID-drop containment, so it REFUSES in production (sec-keystone) and
# only exec's unsandboxed in dev/test with an honest stub_used row. Defined
# BEFORE any call site (CR R2).
_do_exec() {
    if [ "${HOST_OS}" = "linux" ]; then
        if ! command -v runuser >/dev/null 2>&1; then
            printf 'plugin.launcher_uid_drop_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
            exit 1
        fi
        exec runuser -u "${TARGET_UID}" -- "${EXECUTABLE}" "$@"
    fi
    # Non-Linux: no UID-drop is available. Refuse to exec unsandboxed in
    # production with a host-accurate reason (low-1: not the windows_stub key).
    if [ "${IS_PRODUCTION}" = "true" ]; then
        printf 'supervisor.sandbox.refused.uid_separation_unavailable plugin_id=%s host_os=%s\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"uid_separation_unavailable","environment":"production","host_os":"%s"}\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
        exit 1
    fi
    # Dev/test only: exec without UID-drop, with an honest stub_used audit row
    # (low-1: replaces the advisory config_insecure row so the unsandboxed exec
    # is auditable under the same closed vocabulary as the other stub paths).
    printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","host_os":"%s","environment":"%s","reason":"uid_separation_unavailable"}\n' "${PLUGIN_ID}" "${HOST_OS}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
    exec "${EXECUTABLE}" "$@"
}

# Dev escape hatch: refuse in production (devex-001 — operator-visible stderr
# key + SANDBOX_REFUSED audit row). sec-1 truthy parsing.
if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ] && _truthy "${UNSANDBOXED}"; then
    printf 'supervisor.sandbox.unsandboxed_refused_in_production plugin_id=%s\n' "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"unsandboxed_env_set_in_production","environment":"production","host_os":"%s"}\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
    exit 1
fi

# Read the manifest's [sandbox] block via the pre-launcher Python helper. The
# launcher forwards ALFRED_PLUGIN_MANIFEST_PATH as --manifest-path when set,
# else the helper resolves the manifest from the plugin-id.
_read_sandbox() {
    if [ -n "${ALFRED_PLUGIN_MANIFEST_PATH:-}" ]; then
        python3 -m alfred.plugins.manifest_reader --read-sandbox \
            --manifest-path "${ALFRED_PLUGIN_MANIFEST_PATH}"
    else
        python3 -m alfred.plugins.manifest_reader --read-sandbox \
            --plugin-id "${PLUGIN_ID}"
    fi
}

if ! SANDBOX_JSON="$(_read_sandbox 2>/dev/null)"; then
    printf 'supervisor.sandbox.refused.sandbox_block_missing plugin_id=%s\n' "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"sandbox_block_missing","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
    exit 1
fi

# jq parses the helper's JSON. Refuse loudly if missing — the resolver is
# unimplementable without a JSON reader in bash (alfred-core apt-installs jq).
if ! command -v jq >/dev/null 2>&1; then
    printf 'supervisor.sandbox.refused.jq_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
    exit 1
fi

SANDBOX_KIND="$(printf '%s\n' "${SANDBOX_JSON}" | jq -r '.kind')"

case "${SANDBOX_KIND}" in
    full)
        POLICY_REF="$(printf '%s\n' "${SANDBOX_JSON}" | jq -r ".policy_refs.\"${HOST_OS}\" // empty")"
        if [ -z "${POLICY_REF}" ]; then
            printf 'supervisor.sandbox.refused.policy_ref_missing plugin_id=%s host_os=%s\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
            printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"policy_ref_missing","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
            exit 1
        fi
        case "${HOST_OS}" in
            linux)
                # Confine + translate the policy_ref into bwrap flags via the
                # Python helper (sec-2 path-confinement lives in Python). One
                # flag per line into a bash array.
                if ! BWRAP_FLAGS_RAW="$(python3 -m alfred.plugins.manifest_reader --policy-to-bwrap-flags --policy-ref "${POLICY_REF}" 2>&1)"; then
                    printf 'supervisor.sandbox.refused.policy_translate_failed plugin_id=%s detail=%s\n' "${PLUGIN_ID}" "${BWRAP_FLAGS_RAW}" >&2
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"policy_ref_unreadable","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                    exit 1
                fi
                BWRAP_FLAGS=()
                while IFS= read -r _flag; do
                    [ -n "${_flag}" ] && BWRAP_FLAGS+=("${_flag}")
                done <<EOF
${BWRAP_FLAGS_RAW}
EOF
                : "${BWRAP:=bwrap}"
                exec "${BWRAP}" "${BWRAP_FLAGS[@]}" -- "${EXECUTABLE}" "$@"
                ;;
            macos)
                # PR-S4-7 ships the sandbox-exec invocation; PR-S4-6 refuses
                # so the resolver path is well-defined on macOS.
                printf 'supervisor.sandbox.refused.macos_full_not_yet_shipped plugin_id=%s\n' "${PLUGIN_ID}" >&2
                exit 1
                ;;
            windows)
                # kind:full on Windows resolves to a stub policy. Refuse in
                # production; dev emits a stub-used row + execs unsandboxed.
                if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ]; then
                    printf 'supervisor.sandbox.refused.windows_stub_in_production plugin_id=%s\n' "${PLUGIN_ID}" >&2
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"windows_stub_in_production","environment":"production","host_os":"windows"}\n' "${PLUGIN_ID}" >&2
                    exit 1
                fi
                printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","policy_ref":"%s","host_os":"windows","environment":"%s"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                exec "${EXECUTABLE}" "$@"
                ;;
        esac
        ;;
    none)
        # Slice-3 UID-separated baseline (unchanged). fd 3 still inherited by
        # the kernel; the plugin's read_fd3_secret consumes it if present.
        _do_exec "$@"
        ;;
    stub)
        # A kind:stub manifest is host-agnostic — it can resolve on linux/macos/
        # windows alike. low-1: refuse with a host-accurate reason rather than
        # reusing the windows-specific key (which mis-labels the audit row on a
        # linux/macos host).
        if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ]; then
            printf 'supervisor.sandbox.refused.stub_kind_in_production plugin_id=%s host_os=%s\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
            printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"stub_kind_in_production","environment":"production","host_os":"%s"}\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
            exit 1
        fi
        printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","host_os":"%s","environment":"%s"}\n' "${PLUGIN_ID}" "${HOST_OS}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
        exec "${EXECUTABLE}" "$@"
        ;;
    *)
        printf 'supervisor.sandbox.refused.sandbox_block_missing plugin_id=%s\n' "${PLUGIN_ID}" >&2
        exit 1
        ;;
esac
