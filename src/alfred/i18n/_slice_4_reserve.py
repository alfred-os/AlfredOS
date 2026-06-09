"""Slice-4 catalog-key reservation.

Slice-4 consumer PRs (S4-1..S4-10) call ``t()`` on the 44 Slice-4
catalog keys from spec §12.2. PR-S4-0b Component I ships the
catalog ahead of those consumers — without this reservation file,
``pybabel extract -F babel.cfg src/alfred`` sees no source reference
for the new msgids and marks them obsolete (``#~ msgid``) on the next
``pybabel update``, which the CI ``i18n catalog drift`` gate trips on.

Every ``t(...)`` call in ``_register()`` is extracted by Babel as a
msgid reference. The function is never called at runtime; importing
this module is the no-op side-effect the static analyser sees.

When Slice-4 implementation PRs (S4-1..S4-10) land their consuming
``t()`` calls at the real call sites, the corresponding entry in this
file MAY be deleted (cleaner) or LEFT IN PLACE (safer — guards against
a future refactor that drops the consuming call site silently). The
reservation file pattern follows the i18n hygiene baseline.

Source: spec §12.2 (Slice-4 i18n catalog).
"""

from __future__ import annotations

from alfred.i18n import t


def _register() -> None:
    """Reference every Slice-4 catalog key so pybabel sees them as used.

    Never called at runtime. Slice-4 consumer PRs will add real
    ``t()`` calls at the actual call sites; until they land this
    function is the only static reference.
    """
    # Login / session lifecycle (PR-S4-5).
    t("login.prompt_confirm_overwrite")
    t("login.session_overwrite_confirm")
    t("login.user_not_found")
    t("login.user_not_found.hint")
    t("login.expires_in_out_of_range")
    t("login.no_machine_id")
    t("login.confirmed")
    t("logout.no_session")
    t("logout.confirmed")
    t("whoami.no_session")
    t("whoami.expired")
    t("whoami.template")

    # Operator-session refusal reasons (PR-S4-5).
    t("operator_session.refused.expired")
    t("operator_session.refused.host_mismatch")
    t("operator_session.refused.machine_mismatch")
    t("operator_session.refused.token_unknown")
    t("operator_session.refused.user_revoked")
    t("operator_session.refused.bad_file_mode")
    t("operator_session.refused.bad_file_owner")
    t("operator_session.refused.resolver_timeout")

    # Supervisor reset refusals (PR-S4-5).
    t("supervisor.breaker.reset.refused.not_logged_in")
    t("supervisor.breaker.reset.refused.operator_permissions_insufficient")

    # Daemon boot refusals (PR-S4-1).
    t("daemon.boot.environment_not_set")
    t("daemon.boot.unsandboxed_in_production")
    t("daemon.boot.launcher_not_policy_resolving")
    t("daemon.boot.snapshot_ref_init_failed")
    t("daemon.boot.capability_gate_handshake_failed")
    t("daemon.boot.audit_hash_pepper_missing")
    t("daemon.boot.started")
    t("daemon.stop.confirmed")
    t("daemon.status.template")

    # Sandbox refusal reasons (PR-S4-6).
    t("supervisor.sandbox.refused.policy_ref_missing")
    t("supervisor.sandbox.refused.policy_ref_os_mismatch")
    t("supervisor.sandbox.refused.policy_ref_unreadable")
    t("supervisor.sandbox.refused.sandbox_block_missing")
    t("supervisor.sandbox.refused.windows_stub_in_production")
    t("supervisor.sandbox.unsandboxed_refused_in_production")

    # Config-reload notifications (PR-S4-4).
    t("supervisor.config_reload.applied")
    t("supervisor.config_reload.rejected.parse_failure")
    t("supervisor.config_reload.rejected.high_blast_change")
    t("supervisor.config_reload.rejected.validation_failure")
    t("supervisor.config_reload.rejected.file_vanished")
    t("supervisor.config_reload.rejected.stat_failed")
    t("supervisor.config_reload.rejected.audit_write_failed")
    t("supervisor.config_watcher.degraded")
    t("supervisor.config_watcher.recovered")
    # Fallback-sink write failure (PR-S4-4 round-3 err-S4-4-3).
    t("policies.watcher.fallback_write_failed")

    # TUI gating (PR-S4-1).
    t("comms.tui.daemon_required_to_chat")
