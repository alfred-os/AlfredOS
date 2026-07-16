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
#                    translate to bwrap flags, exec bwrap. fd 3 (the provider-
#                    key channel) is inherited into the sandbox by bwrap's
#                    default fd inheritance — NO --sync-fd/--keep-fd flag is
#                    emitted (--sync-fd would consume fd 3; verified bwrap
#                    0.8.0/0.9.0, issue #218).
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
        # #435: emit a row so a malformed-id PROBE leaves an audit trail (it left
        # none before). D2: the row carries the launcher-authored `<invalid>`
        # sentinel, NEVER ${PLUGIN_ID} — interpolating the tainted bytes into this
        # template is exactly the injection the gate above exists to prevent (CR on
        # PR #140), and `<`/`>` are outside the id charset so it cannot collide with
        # a real id. environment/host_os are not resolved yet at this point, so they
        # carry the same unset/unknown markers as the environment-failure row below.
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"<invalid>","reason":"plugin_id_charset_invalid","environment":"unset","host_os":"unknown"}\n' >&2
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
    # CR #229 R2 finding-10: emit the structured audit row too, matching the
    # other refusal rows' shape so the audit trail is consistent across every
    # sandbox refusal reason.
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"unknown_host_os","environment":"%s","host_os":"unknown"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
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
            # #435 / D6: a Linux host that SUPPORTS UID-drop but lacks util-linux —
            # distinct from uid_separation_unavailable (an OS with no mechanism at
            # all), because the remediation differs.
            printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"runuser_unavailable","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
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

# #434A: capture the helper's stderr instead of discarding it. `_read_sandbox`
# can fail with FIVE distinct bare i18n keys; `2>/dev/null` collapsed all five
# into the benign `sandbox_block_missing`, so `manifest_unreadable` /
# `manifest_invalid` — a planted-manifest TAMPER signal — were recorded as "you
# forgot [sandbox]". Mirrors the environment path above (L155-171), which has
# implemented this capture-and-map correctly since PR #229.
_SANDBOX_ERR_FILE="$(mktemp "${TMPDIR:-/tmp}/alfred-launcher-sandbox-err.XXXXXX")"
if ! SANDBOX_JSON="$(_read_sandbox 2>"${_SANDBOX_ERR_FILE}")"; then
    _sandbox_err_key="$(tail -n 1 "${_SANDBOX_ERR_FILE}" 2>/dev/null || true)"
    rm -f "${_SANDBOX_ERR_FILE}"
    # Each arm assigns BOTH the audit reason and the operator key it re-prints.
    # The operator key is echoed VERBATIM (never synthesised from the reason) so
    # no new i18n key is needed — the `plugin.*` keys are already registered in
    # _sandbox_i18n.py, and a `t(message_key=var)` indirection would make them
    # pybabel-invisible. Closed vocab: audit_row_schemas.SANDBOX_REFUSED_REASONS;
    # bound by test_sandbox_reason_vocab_sync.py (#432).
    case "${_sandbox_err_key}" in
        plugin.launcher_plugin_id_invalid) _SANDBOX_REASON="plugin_id_charset_invalid" ;;
        plugin.manifest_reader_no_source) _SANDBOX_REASON="manifest_reader_no_source" ;;
        plugin.manifest_unreadable) _SANDBOX_REASON="manifest_unreadable" ;;
        plugin.manifest_sandbox_block_missing) _SANDBOX_REASON="sandbox_block_missing" ;;
        plugin.manifest_invalid) _SANDBOX_REASON="manifest_invalid" ;;
        *)
            # An empty or unrecognised capture is a drift/crash ALARM, not a
            # routine refusal — say so rather than guessing a specific reason
            # (fail-closed: we still refuse).
            _SANDBOX_REASON="reason_unclassified"
            _sandbox_err_key="supervisor.sandbox.refused.reason_unclassified"
            ;;
    esac
    printf '%s plugin_id=%s\n' "${_sandbox_err_key}" "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"%s","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${_SANDBOX_REASON}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
    exit 1
fi
rm -f "${_SANDBOX_ERR_FILE}"

# jq parses the helper's JSON. Refuse loudly if missing — the resolver is
# unimplementable without a JSON reader in bash (alfred-core apt-installs jq).
if ! command -v jq >/dev/null 2>&1; then
    printf 'supervisor.sandbox.refused.jq_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"jq_unavailable","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
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

        # #437: POLICY_REF is interpolated raw into the audit-JSON printf rows
        # below (and passed to the flags subprocess). PLUGIN_ID is charset-gated
        # at entry for exactly this reason; do the same for POLICY_REF here, at
        # its single chokepoint, BEFORE any use. Refuse WITHOUT echoing the
        # tainted value — emitting it into the JSON row would BE the injection.
        # Same negated path-safe class as the Python producer (manifest.py).
        case "${POLICY_REF}" in
            *[!A-Za-z0-9._/-]*)
                printf 'supervisor.sandbox.refused.policy_ref_charset_invalid plugin_id=%s\n' "${PLUGIN_ID}" >&2
                printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"policy_ref_charset_invalid","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
                exit 1
                ;;
        esac

        case "${HOST_OS}" in
            linux)
                # Confine + translate the policy_ref into bwrap flags via the
                # Python helper (sec-2 path-confinement lives in Python). One
                # flag per line into a bash array.
                if ! BWRAP_FLAGS_RAW="$(python3 -m alfred.plugins.manifest_reader --policy-to-bwrap-flags --policy-ref "${POLICY_REF}" 2>&1)"; then
                    # #428: the helper printed the SCHEMA reason (bare, or a
                    # supervisor.sandbox.refused.* key) as its last stderr line; a
                    # cold-import warning may precede it, so read the LAST line. Echo
                    # the real reason into the audit row instead of the historic
                    # hardcoded policy_ref_unreadable, which mislabelled every schema
                    # refusal. Closed vocab: audit_row_schemas.SANDBOX_REFUSED_REASONS;
                    # both case lists + every emit path are bound to it by
                    # test_sandbox_reason_vocab_sync.py (#432).
                    _CAPTURED_REASON="$(printf '%s\n' "${BWRAP_FLAGS_RAW}" | tail -n 1)"
                    _CAPTURED_REASON="${_CAPTURED_REASON#supervisor.sandbox.refused.}"
                    case "${_CAPTURED_REASON}" in
                        kind_full_requires_keep_fd_3|policy_path_not_absolute|arch_variable_path_hard_bound|mount_shadows_earlier_mount|soft_bind_forbidden_path|bind_source_too_broad|policy_translate_failed|policy_ref_escapes_root|policy_ref_unreadable)
                            _AUDIT_REASON="${_CAPTURED_REASON}" ;;
                        *)
                            # #434B: an unclassifiable last line is a drift/crash ALARM — a
                            # traceback, an ImportError, or a schema reason added to Python
                            # without touching this case. Record it as such. Reusing
                            # `policy_translate_failed` (which is ALSO the real reason for
                            # malformed TOML) made the alarm indistinguishable from a routine
                            # policy-authoring error, so nobody ever looked at it.
                            _AUDIT_REASON="reason_unclassified" ;;
                    esac
                    # #434B: printed AFTER the case resolves _AUDIT_REASON so the operator
                    # key matches the recorded reason, rather than unconditionally naming
                    # policy_translate_failed even when the real (or unclassified) reason is
                    # something else. Every value _AUDIT_REASON can take here has a
                    # registered supervisor.sandbox.refused.* catalog key — bound by
                    # test_every_schema_case_reason_has_a_registered_operator_key.
                    printf 'supervisor.sandbox.refused.%s plugin_id=%s detail=%s\n' "${_AUDIT_REASON}" "${PLUGIN_ID}" "${BWRAP_FLAGS_RAW}" >&2
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"%s","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${_AUDIT_REASON}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                    exit 1
                fi
                BWRAP_FLAGS=()
                while IFS= read -r _flag; do
                    [ -n "${_flag}" ] && BWRAP_FLAGS+=("${_flag}")
                done <<EOF
${BWRAP_FLAGS_RAW}
EOF
                : "${BWRAP:=bwrap}"
                # OPT-IN interpreter-prefix bind (CR #250). `EXECUTABLE` is the
                # generic exec target for EVERY kind:full plugin, so binding
                # dirname(dirname(realpath)) UNCONDITIONALLY would widen the sandbox
                # for any plugin (a repo-root or shallow-path exec → an unintended
                # host subtree). The extra bind is scoped to callers that explicitly
                # opt in via ALFRED_SANDBOX_BIND_INTERP_PREFIX=1 — only the
                # quarantine-child spawn (`_child_env` in quarantine_child_io.py)
                # sets it, because only it execs a bound interpreter that may live
                # OUTSIDE the policy's static binds (/usr and /lib hard, /lib64
                # softly via --ro-bind-try — #269) — a proto/uv self-contained
                # python-build-standalone under ~/.proto: interpreter
                # + stdlib + site-packages share one prefix — ADR-0030). Generic
                # kind:full plugins run under a /usr interpreter the policy already
                # binds, so they DON'T opt in and the namespace is never widened for
                # them. Read-only; the interpreter is operator-configured (the spawn's
                # <executable> arg), never attacker-controlled.
                EXTRA_BINDS=()
                EXEC_TARGET="${EXECUTABLE}"
                if _truthy "${ALFRED_SANDBOX_BIND_INTERP_PREFIX:-}"; then
                    _INTERP_REAL="$(readlink -f "${EXECUTABLE}")"
                    _INTERP_PREFIX="$(dirname "$(dirname "${_INTERP_REAL}")")"
                    # #428: the over-broad-prefix decision lives in ONE place —
                    # is_over_broad_bind_source, reached via --check-bind-source — so
                    # the schema and the launcher cannot drift. Refuses "" (empty
                    # prefix), "/", any non-allowlisted top-level root, and pseudo-fs
                    # sources. Output is discarded; the exit code is the verdict.
                    if ! python3 -m alfred.plugins.manifest_reader --check-bind-source --bind-source "${_INTERP_PREFIX}" >/dev/null 2>&1; then
                        printf 'supervisor.sandbox.refused.interpreter_prefix_too_broad plugin_id=%s interpreter=%s prefix=%s\n' "${PLUGIN_ID}" "${_INTERP_REAL}" "${_INTERP_PREFIX}" >&2
                        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"interpreter_prefix_too_broad","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
                        exit 1
                    fi
                    EXTRA_BINDS=(--ro-bind "${_INTERP_PREFIX}" "${_INTERP_PREFIX}")
                    # Exec the realpath: a uv-venv symlink target is outside the
                    # bound prefix and fails execvp under bwrap (ADR-0030).
                    EXEC_TARGET="${_INTERP_REAL}"
                fi
                # ``set -u`` + an empty bash array: Bash 3.2 (the /bin/bash on
                # macOS) raises "unbound variable" when expanding "${arr[@]}" for a
                # declared-but-empty array. The ``${arr[@]+"${arr[@]}"}`` guard
                # expands to nothing when the array is empty and to its elements
                # (word-per-element, quoted) otherwise — safe on Bash 3.2 AND Bash
                # 4/5 (Linux), and byte-identical to an unguarded expansion wherever
                # the array is non-empty. EXTRA_BINDS is empty unless the
                # interp-prefix opt-in ran; BWRAP_FLAGS is empty only for a
                # zero-flag policy. (Surfaced by the macOS unit CI leg, #246.)
                # #435 / D5: refuse explicitly rather than letting `exec` fail at 127
                # with no audit row. Mirrors the jq check above. `command -v` honours
                # both a bare `bwrap` on PATH and a BWRAP= absolute-path override.
                if ! command -v "${BWRAP}" >/dev/null 2>&1; then
                    printf 'supervisor.sandbox.refused.bwrap_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"bwrap_unavailable","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                    exit 1
                fi
                exec "${BWRAP}" \
                    ${BWRAP_FLAGS[@]+"${BWRAP_FLAGS[@]}"} \
                    ${EXTRA_BINDS[@]+"${EXTRA_BINDS[@]}"} \
                    -- "${EXEC_TARGET}" "$@"
                ;;
            macos)
                # PR-S4-7 ships the sandbox-exec invocation; until then refuse so
                # the resolver path is well-defined on macOS.
                printf 'supervisor.sandbox.refused.macos_full_not_yet_shipped plugin_id=%s\n' "${PLUGIN_ID}" >&2
                printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"macos_full_not_yet_shipped","environment":"%s","host_os":"macos"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
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
                printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","policy_ref":"%s","host_os":"windows","environment":"%s","reason":"windows_stub"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
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
        printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","host_os":"%s","environment":"%s","reason":"stub_kind"}\n' "${PLUGIN_ID}" "${HOST_OS}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
        exec "${EXECUTABLE}" "$@"
        ;;
    *)
        # #435: a kind outside {full,none,stub} — jq yielded null or an unknown
        # value. Previously recorded under the "no [sandbox] block" reason, which
        # is a different condition with a different fix. Fail-closed default.
        printf 'supervisor.sandbox.refused.sandbox_kind_unrecognised plugin_id=%s\n' "${PLUGIN_ID}" >&2
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"sandbox_kind_unrecognised","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
        exit 1
        ;;
esac
