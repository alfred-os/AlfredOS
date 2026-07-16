"""Pybabel-visible registry for sandbox-launcher i18n keys (PR-S4-6).

The policy-resolving launcher (``bin/alfred-plugin-launcher.sh``) and its
pre-launcher Python helper (``manifest_reader.py``) emit closed-vocabulary
refusal identifiers on stderr as BARE keys — the supervisor renders them
against the catalog at audit-emit time. ``manifest_reader`` prints the keys
via ``print()`` (not ``t()``) so the bytes hit stderr verbatim, and bash
cannot be parsed by ``pybabel extract`` at all.

This module exists purely so each such key has a matching ``t("literal")``
callsite for pybabel to extract, keeping the keys in the active catalog
(otherwise ``pybabel update`` re-marks them ``#~`` obsolete and the
supervisor renders the raw msgid back to the operator). Mirrors the
established :mod:`alfred.plugins._launcher_i18n` pattern.

The boot-posture keys (``supervisor.boot.*``, ``daemon.boot.environment_source_conflict``)
are emitted at the daemon-boot caller (PR-S4-1) from the
``MlockResult`` / conflict primitives this PR ships; their callsites live
here so the catalog carries them from PR-S4-6 onward.

low-2 (CR PR #229): the launcher also surfaces ``daemon.boot.environment_not_set``
and ``daemon.boot.environment_unrecognised`` on its environment-read refusal
path (it captures the helper's stderr and re-prints the specific key). Those
two keys are emitted by ``manifest_reader._cmd_read_environment`` and rendered
elsewhere (the daemon-boot CLI, PR-S4-1) — their pybabel visibility relies on
those external callsites, NOT this registry. They are listed in the
``_ENVIRONMENT_KEYS_RENDERED_ELSEWHERE`` note below so the dependency is named
rather than silently assumed.
"""

from __future__ import annotations

from alfred.i18n import t

#: Sandbox-launcher + manifest-reader refusal/observability keys. Each entry
#: is a key the launcher (or manifest_reader) prints to stderr, paired with a
#: no-arg ``t()`` call pybabel can extract. Values are discarded — the
#: supervisor re-renders each key with its own kwargs at audit-emit time.
_SANDBOX_VISIBLE_KEYS: dict[str, str] = {
    # manifest_reader refusals (printed, not via t()).
    "plugin.manifest_unreadable": t("plugin.manifest_unreadable"),
    "plugin.manifest_reader_no_source": t("plugin.manifest_reader_no_source"),
    "plugin.manifest_invalid": t("plugin.manifest_invalid"),
    # launcher + manifest_reader sandbox refusals (bash-emitted bare keys).
    "supervisor.sandbox.refused.policy_ref_escapes_root": t(
        "supervisor.sandbox.refused.policy_ref_escapes_root"
    ),
    "supervisor.sandbox.refused.policy_ref_unreadable": t(
        "supervisor.sandbox.refused.policy_ref_unreadable"
    ),
    # #437: launcher defense-in-depth charset guard on POLICY_REF (mirrors the
    # manifest.py producer-side _POLICY_REF_BAD_CHAR validator).
    "supervisor.sandbox.refused.policy_ref_charset_invalid": t(
        "supervisor.sandbox.refused.policy_ref_charset_invalid"
    ),
    "supervisor.sandbox.refused.unknown_host_os": t("supervisor.sandbox.refused.unknown_host_os"),
    "supervisor.sandbox.refused.jq_unavailable": t("supervisor.sandbox.refused.jq_unavailable"),
    # #435: a missing bwrap previously failed the exec at 127 with no row.
    "supervisor.sandbox.refused.bwrap_unavailable": t(
        "supervisor.sandbox.refused.bwrap_unavailable"
    ),
    "supervisor.sandbox.refused.macos_full_not_yet_shipped": t(
        "supervisor.sandbox.refused.macos_full_not_yet_shipped"
    ),
    "supervisor.sandbox.refused.policy_translate_failed": t(
        "supervisor.sandbox.refused.policy_translate_failed"
    ),
    # #434B: the schema `case`'s allow-list arm (sandbox_policy.py
    # SandboxPolicyInvalid reasons, re-emitted by the launcher's operator
    # stderr key since the printf now interpolates ${_AUDIT_REASON} rather
    # than hardcoding policy_translate_failed). Bound by
    # test_every_schema_case_reason_has_a_registered_operator_key.
    "supervisor.sandbox.refused.kind_full_requires_keep_fd_3": t(
        "supervisor.sandbox.refused.kind_full_requires_keep_fd_3"
    ),
    "supervisor.sandbox.refused.policy_path_not_absolute": t(
        "supervisor.sandbox.refused.policy_path_not_absolute"
    ),
    "supervisor.sandbox.refused.arch_variable_path_hard_bound": t(
        "supervisor.sandbox.refused.arch_variable_path_hard_bound"
    ),
    "supervisor.sandbox.refused.mount_shadows_earlier_mount": t(
        "supervisor.sandbox.refused.mount_shadows_earlier_mount"
    ),
    "supervisor.sandbox.refused.soft_bind_forbidden_path": t(
        "supervisor.sandbox.refused.soft_bind_forbidden_path"
    ),
    "supervisor.sandbox.refused.bind_source_too_broad": t(
        "supervisor.sandbox.refused.bind_source_too_broad"
    ),
    # #434B: the honest fallback when the helper's stderr line is unclassifiable
    # (a traceback, an ImportError, a new unbound reason). Distinct from
    # policy_translate_failed so a drift/crash ALARM is forensically separable
    # from a routine malformed-TOML refusal.
    "supervisor.sandbox.refused.reason_unclassified": t(
        "supervisor.sandbox.refused.reason_unclassified"
    ),
    # #250 / ADR-0030: the kind=full bwrap exec binds the configured interpreter's
    # install prefix into the sandbox; a root-level interpreter (prefix "/" or
    # empty) would ro-bind the entire host root, so the launcher refuses loudly.
    "supervisor.sandbox.refused.interpreter_prefix_too_broad": t(
        "supervisor.sandbox.refused.interpreter_prefix_too_broad"
    ),
    # sec-keystone (CR PR #229 finding-1): FAKE_UNAME set in production is a
    # loud refusal (the shim is ignored there); the non-Linux _do_exec branch
    # refuses in production when no UID-drop containment is available; and the
    # kind:stub production refusal now uses a host-accurate reason (low-1)
    # rather than reusing the windows-specific key.
    "supervisor.sandbox.refused.fake_uname_in_production": t(
        "supervisor.sandbox.refused.fake_uname_in_production"
    ),
    "supervisor.sandbox.refused.uid_separation_unavailable": t(
        "supervisor.sandbox.refused.uid_separation_unavailable"
    ),
    "supervisor.sandbox.refused.stub_kind_in_production": t(
        "supervisor.sandbox.refused.stub_kind_in_production"
    ),
    # #435: previously refused with no audit row at all.
    "supervisor.sandbox.refused.sandbox_kind_unrecognised": t(
        "supervisor.sandbox.refused.sandbox_kind_unrecognised"
    ),
    # Boot-posture observability (emitted at the PR-S4-1 daemon-boot caller
    # from the primitives PR-S4-6 ships).
    "supervisor.boot.mlock_unavailable": t("supervisor.boot.mlock_unavailable"),
    "supervisor.boot.core_dumps_disabled": t("supervisor.boot.core_dumps_disabled"),
    "daemon.boot.environment_source_conflict": t("daemon.boot.environment_source_conflict"),
}


#: low-2: keys the launcher re-prints on its environment-read refusal path but
#: whose pybabel-visible ``t()`` callsites live elsewhere (the daemon-boot CLI /
#: ``manifest_reader``). Named here so the docstring's claim is concrete and a
#: future reader can trace where each key's catalog reference actually lives.
_ENVIRONMENT_KEYS_RENDERED_ELSEWHERE: tuple[str, ...] = (
    "daemon.boot.environment_not_set",  # _slice_4_reserve.py + manifest_reader
    "daemon.boot.environment_unrecognised",  # _slice_4_reserve.py + manifest_reader
)


__all__ = ["_ENVIRONMENT_KEYS_RENDERED_ELSEWHERE", "_SANDBOX_VISIBLE_KEYS"]
