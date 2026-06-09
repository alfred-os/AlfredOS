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
    "supervisor.sandbox.refused.unknown_host_os": t("supervisor.sandbox.refused.unknown_host_os"),
    "supervisor.sandbox.refused.jq_unavailable": t("supervisor.sandbox.refused.jq_unavailable"),
    "supervisor.sandbox.refused.macos_full_not_yet_shipped": t(
        "supervisor.sandbox.refused.macos_full_not_yet_shipped"
    ),
    "supervisor.sandbox.refused.policy_translate_failed": t(
        "supervisor.sandbox.refused.policy_translate_failed"
    ),
    # Boot-posture observability (emitted at the PR-S4-1 daemon-boot caller
    # from the primitives PR-S4-6 ships).
    "supervisor.boot.mlock_unavailable": t("supervisor.boot.mlock_unavailable"),
    "supervisor.boot.core_dumps_disabled": t("supervisor.boot.core_dumps_disabled"),
    "daemon.boot.environment_source_conflict": t("daemon.boot.environment_source_conflict"),
}


__all__ = ["_SANDBOX_VISIBLE_KEYS"]
