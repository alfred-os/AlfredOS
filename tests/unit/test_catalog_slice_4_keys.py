"""Every Slice-4 ``t()`` key resolves to a non-bare value.

Mirrors the Slice-3 ``test_catalog_slice3_keys.py`` discipline. The
catalog ships in PR-S4-0b Component I; implementation PRs (S4-1..S4-10)
consume the keys. CI's ``pybabel compile --check`` enforces no orphan
``t()`` calls in source; this test enforces no orphan key in the
catalog.

The 44 keys span 7 families:
* Login / session lifecycle (12) — PR-S4-5 ``alfred login`` / ``logout``
  / ``whoami``.
* Operator-session refusal reasons (8) — PR-S4-5 ``_resolve_operator``
  + ADR-0024 budget.
* Supervisor reset refusals (2) — PR-S4-5 reset-permission gate.
* Daemon boot refusals (9) — PR-S4-1 ``alfred daemon start`` (includes
  the ``audit_hash_pepper_missing`` refusal from PR #205 round-2
  sec-3 closure).
* Sandbox refusal reasons (6) — PR-S4-6 launcher.
* Config-reload notifications (6) — PR-S4-4 hot-reload.
* TUI gating (1) — PR-S4-1 daemon split.
"""

from __future__ import annotations

from alfred.i18n import t

SLICE_4_KEYS: tuple[str, ...] = (
    # Login / session lifecycle (12) — spec §12.2.
    "login.prompt_confirm_overwrite",
    "login.session_overwrite_confirm",
    "login.user_not_found",
    "login.user_not_found.hint",
    "login.expires_in_out_of_range",
    "login.no_machine_id",
    "login.confirmed",
    "logout.no_session",
    "logout.confirmed",
    "whoami.no_session",
    "whoami.expired",
    "whoami.template",
    # Operator-session refusal reasons (8).
    "operator_session.refused.expired",
    "operator_session.refused.host_mismatch",
    "operator_session.refused.machine_mismatch",
    "operator_session.refused.token_unknown",
    "operator_session.refused.user_revoked",
    "operator_session.refused.bad_file_mode",
    "operator_session.refused.bad_file_owner",
    "operator_session.refused.resolver_timeout",
    # Supervisor reset refusals (2).
    "supervisor.breaker.reset.refused.not_logged_in",
    "supervisor.breaker.reset.refused.operator_permissions_insufficient",
    # Daemon boot (9 — includes audit_hash_pepper_missing per round-2
    # sec-3 + arch-002 closures).
    "daemon.boot.environment_not_set",
    "daemon.boot.unsandboxed_in_production",
    "daemon.boot.launcher_not_policy_resolving",
    "daemon.boot.snapshot_ref_init_failed",
    "daemon.boot.capability_gate_handshake_failed",
    "daemon.boot.audit_hash_pepper_missing",  # PR #205 round-2 sec-3 closure
    "daemon.boot.started",
    "daemon.stop.confirmed",
    "daemon.status.template",
    # Daemon CLI surface keys added by PR-S4-1 (#174) beyond the reserve.
    "daemon.boot.audit_log_unwritable",
    "daemon.stop.no_daemon",
    "daemon.stop.stale_pidfile",
    "daemon.status.not_running",
    "daemon.status.stale_pidfile",
    "daemon.help.root",
    "daemon.help.start",
    "daemon.help.stop",
    "daemon.status.help",
    # Sandbox refusal reasons (6).
    "supervisor.sandbox.refused.policy_ref_missing",
    "supervisor.sandbox.refused.policy_ref_os_mismatch",
    "supervisor.sandbox.refused.policy_ref_unreadable",
    "supervisor.sandbox.refused.sandbox_block_missing",
    "supervisor.sandbox.refused.windows_stub_in_production",
    "supervisor.sandbox.unsandboxed_refused_in_production",
    # Config-reload notifications (6).
    "supervisor.config_reload.applied",
    "supervisor.config_reload.rejected.parse_failure",
    "supervisor.config_reload.rejected.high_blast_change",
    "supervisor.config_reload.rejected.validation_failure",
    "supervisor.config_reload.rejected.file_vanished",
    "supervisor.config_reload.rejected.stat_failed",
    # TUI (1).
    "comms.tui.daemon_required_to_chat",
)


def test_all_slice_4_keys_resolve_to_non_bare_strings() -> None:
    """Every Slice-4 key resolves to something other than the key itself.

    ``t(key)`` returns ``key`` verbatim when the catalog has no entry —
    the canonical "bare key" signal. This test enumerates the keys
    PR-S4-1..S4-10 will consume and refuses any that the catalog leaves
    bare.
    """
    bare: list[str] = []
    for key in SLICE_4_KEYS:
        msg = t(key)
        if msg == key:
            bare.append(key)
    assert not bare, f"Slice-4 catalog keys without translations (returned bare): {bare}"


def test_slice_4_keys_count_at_floor() -> None:
    """The Slice-4 catalog ships at least 44 keys (the spec §12.2 floor).

    Counted at planning-time as the floor of the slice's i18n surface
    area. Downstream PRs may add MORE keys but MUST NOT subtract these.
    A regression here means a Slice-4 consumer is silently emitting a
    bare key in operator-facing output.
    """
    assert len(SLICE_4_KEYS) >= 44, (
        f"Slice-4 catalog enumeration count {len(SLICE_4_KEYS)} < 44 floor"
    )


def test_no_duplicate_keys_in_slice_4_enumeration() -> None:
    """Keys are unique within the Slice-4 family. A duplicate would mean
    one entry silently shadows another in the catalog."""
    assert len(SLICE_4_KEYS) == len(set(SLICE_4_KEYS)), (
        f"duplicate Slice-4 keys: {sorted(k for k in SLICE_4_KEYS if SLICE_4_KEYS.count(k) > 1)}"
    )


def test_slice_4_keys_use_dotted_prefix_namespacing() -> None:
    """Every Slice-4 key uses a dotted-namespace prefix.

    Catalog hygiene: bare keys without a domain prefix would be hard
    to search for in operator-facing output and would collide across
    subsystems.
    """
    bare_keys = [k for k in SLICE_4_KEYS if "." not in k]
    assert not bare_keys, f"Slice-4 keys missing dotted prefix: {bare_keys}"


def test_no_orphan_slice_4_msgids_in_po_outside_enumeration() -> None:
    """Reverse drift check: every Slice-4-shaped msgid in alfred.po is in
    ``SLICE_4_KEYS``.

    Closes the test-engineer MED finding from PR #216 review: only the
    forward direction (enumeration ⊆ catalog) was checked; a .po-only
    addition would slip through. This test scans the .po file for
    msgids matching one of the 7 Slice-4 family prefixes and asserts
    the resulting set equals the enumeration.

    Drift in EITHER direction surfaces here as a non-empty diff set.
    """
    import re
    from pathlib import Path

    po_path = Path("locale/en/LC_MESSAGES/alfred.po")
    po_text = po_path.read_text()
    # Match active msgids only — skip commented (``#~ msgid``) historical
    # entries which are kept for translator context.
    msgid_pattern = re.compile(r'^msgid\s+"([^"]+)"', re.MULTILINE)
    all_active_msgids = set(msgid_pattern.findall(po_text))
    # The 7 family prefixes Slice-4 uses (matches the SLICE_4_KEYS tuple
    # families above). Any msgid carrying one of these prefixes that
    # isn't in SLICE_4_KEYS is an orphan.
    slice_4_prefixes = (
        "login.",
        "logout.",
        "whoami.",
        "operator_session.",
        "supervisor.breaker.reset.",
        "supervisor.sandbox.",
        "supervisor.config_reload.",
        "daemon.",
        "comms.tui.daemon_required_to_chat",
    )
    slice_4_msgids_in_po = {
        m for m in all_active_msgids if any(m.startswith(prefix) for prefix in slice_4_prefixes)
    }
    enumeration = set(SLICE_4_KEYS)
    orphans_in_po = slice_4_msgids_in_po - enumeration
    missing_from_po = enumeration - slice_4_msgids_in_po
    assert not orphans_in_po, (
        f"Slice-4-shaped msgids in .po not in SLICE_4_KEYS: {sorted(orphans_in_po)}"
    )
    assert not missing_from_po, (
        f"Slice-4 enumeration keys missing from .po: {sorted(missing_from_po)}"
    )
