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
    t("login.session_overwrite_confirm")
    t("login.user_not_found")
    t("login.user_not_found.hint")
    t("login.expires_in_out_of_range")
    t("login.no_machine_id")
    t("login.confirmed")
    t("login.no_users_exist")
    t("login.auto_selected_single_user")
    t("login.non_tty_requires_explicit_user")
    t("login.refresh_no_session")
    t("login.picker_row")
    t("login.picker_prompt")
    t("login.picker_out_of_range")
    t("logout.no_session")
    t("logout.confirmed")
    t("whoami.no_session")
    t("whoami.expired")
    t("whoami.unloadable")
    t("whoami.unloadable.recovery")
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
    # Refusal recovery companions — each carries a runnable command (devex-2).
    t("operator_session.refused.expired.recovery")
    t("operator_session.refused.host_mismatch.recovery")
    t("operator_session.refused.machine_mismatch.recovery")
    t("operator_session.refused.token_unknown.recovery")
    t("operator_session.refused.user_revoked.recovery")
    t("operator_session.refused.bad_file_mode.recovery")
    t("operator_session.refused.bad_file_owner.recovery")
    t("operator_session.refused.resolver_timeout.recovery")

    # CR-227 round-2 finding 1: the supervisor maps EVERY concrete
    # OperatorSessionError subclass to its own refusal message (no
    # default-to-missing). These keys cover the subclasses the resolver vocab
    # did not yet localise + a distinct unknown-subclass fallback.
    t("operator_session.refused.token_user_mismatch")
    t("operator_session.refused.malformed")
    t("operator_session.refused.parent_dir_insecure")
    t("operator_session.refused.parent_dir_not_owned")
    t("operator_session.refused.revoked")
    t("operator_session.refused.no_machine_id")
    # CR-227 round-3 finding 1 (KEYSTONE): short/misconfigured ``audit.hash_pepper``
    # is a TYPED refusal (no untyped ValueError escapes resolve()).
    t("operator_session.refused.pepper_misconfigured")
    t("operator_session.refused.unknown")
    t("operator_session.refused.token_user_mismatch.recovery")
    t("operator_session.refused.malformed.recovery")
    t("operator_session.refused.parent_dir_insecure.recovery")
    t("operator_session.refused.parent_dir_not_owned.recovery")
    t("operator_session.refused.revoked.recovery")
    t("operator_session.refused.no_machine_id.recovery")
    t("operator_session.refused.pepper_misconfigured.recovery")
    t("operator_session.refused.unknown.recovery")
    # CR-227 round-2 finding 4: best-effort macOS machine-id cache write
    # failure is logged (operator-visible) but never breaks login.
    t("operator_session.machine_id.cache_write_failed", path="/var/db/alfred/machine-id")

    # Supervisor reset refusals (PR-S4-5).
    t("supervisor.breaker.reset.refused.not_logged_in")
    t("supervisor.breaker.reset.refused.not_logged_in.recovery")
    t("supervisor.breaker.reset.refused.operator_permissions_insufficient")
    # Reviewer-gated CLI operator-attribution refusals (PR-S4-5 #153) — the
    # ``t()`` call sites pass these via a ``refusal_key`` variable, so pybabel
    # cannot extract them at the call site; reserve them here.
    t("cli.config.set.refused.not_logged_in")
    t("cli.config.set.refused.not_logged_in.recovery")
    t("cli.plugin.grant.refused.not_logged_in")
    t("cli.plugin.grant.refused.not_logged_in.recovery")

    # Daemon boot refusals (PR-S4-1).
    t("daemon.boot.environment_not_set")
    t("daemon.boot.unsandboxed_in_production")
    t("daemon.boot.launcher_not_policy_resolving")
    t("daemon.boot.snapshot_ref_init_failed")
    t("daemon.boot.capability_gate_handshake_failed")
    t("daemon.boot.audit_hash_pepper_missing")
    t("daemon.boot.started")
    # Core lifecycle signal (Spec A G1 / ADR-0033). The real call sites live in
    # alfred.cli.daemon._commands (_emit_ready / _emit_going_down); reserved
    # here too so the catalog drift gate is satisfied even if a refactor drops
    # a call site.
    t("daemon.lifecycle.ready")
    t("daemon.lifecycle.going_down")
    t("daemon.stop.confirmed")
    t("daemon.status.template")

    # Sandbox refusal reasons (PR-S4-6).
    t("supervisor.sandbox.refused.policy_ref_missing")
    t("supervisor.sandbox.refused.policy_ref_os_mismatch")
    # policy_ref_unreadable lives in plugins/_sandbox_i18n.py alongside its
    # sibling manifest_reader/launcher bare-key refusals (CR PR #229 R3).
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

    # Chat gating (PR-S4-1; re-pointed daemon->gateway in Spec A G5).
    t("comms.tui.gateway_required_to_chat")

    # Comms socket peer-auth (Spec A G3-1 / ADR-0032). The listener
    # (alfred.plugins.comms_socket_transport) logs this via structlog on a
    # mismatched-uid accept reject; the DAEMON-side audit row that consumes it
    # lands in G3-2 (the daemon caller owns the audit writer). G3-2 (devex-263-001)
    # enriches the message with ``expected_uid`` + an actionable next-step so an
    # operator can act on it.
    t("comms.socket.peer_uid_rejected", peer_uid=1000, expected_uid=501)
