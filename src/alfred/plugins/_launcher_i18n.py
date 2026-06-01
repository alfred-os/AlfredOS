"""Pybabel-visible launcher i18n key registry (CR-142 round-3 doc-001).

The plugin launcher (``bin/alfred-plugin-launcher.sh``) emits closed-
vocabulary refusal and config-insecure identifiers on stderr — bare
keys like ``plugin.launcher_plugin_id_invalid`` that the supervisor (a
future PR-S3-3b module) renders against the catalog when persisting
the matching audit row. Because ``pybabel extract`` only follows
``t("literal")`` calls in Python AST and does not parse shell scripts,
the launcher's keys would otherwise drift out of the active catalog
(re-marked ``#~`` obsolete on every ``pybabel update`` pass) and the
supervisor's lookup would silently render the raw msgid string back to
the operator.

This module exists purely so each launcher key has a matching
``t("literal")`` callsite for pybabel to extract. The values are
discarded — the supervisor re-renders each key with its own kwargs at
audit-emit time. The runtime check
``if t_key not in _LAUNCHER_VISIBLE_KEYS`` is the typo-guard the
supervisor will wire in when PR-S3-3b lands.

Mirrors the same pattern used by
:data:`alfred.comms.discord._PYBABEL_VISIBLE_KEYS` for dynamically
dispatched Discord refusal keys.
"""

from __future__ import annotations

from alfred.i18n import t

#: Refusal keys the launcher emits on documented reject paths. Each
#: entry is a key the launcher prints to stderr followed by a no-arg
#: ``t()`` call that pybabel can extract. The supervisor (PR-S3-3b)
#: reads the stderr key, looks it up here as a typo-guard, then
#: renders ``t(key, **kwargs)`` with the operator-facing audit row.
_LAUNCHER_VISIBLE_KEYS: dict[str, str] = {
    "plugin.launcher_plugin_id_invalid": t("plugin.launcher_plugin_id_invalid"),
    "plugin.launcher_unsandboxed_rejected": t("plugin.launcher_unsandboxed_rejected"),
    "plugin.launcher_no_sandbox_policy": t("plugin.launcher_no_sandbox_policy"),
    "plugin.launcher_uid_drop_unavailable": t("plugin.launcher_uid_drop_unavailable"),
    "plugin.launcher_insecure_unsandboxed_dev": t("plugin.launcher_insecure_unsandboxed_dev"),
    "plugin.launcher_insecure_uid_separation_macos": t(
        "plugin.launcher_insecure_uid_separation_macos"
    ),
}


__all__ = ["_LAUNCHER_VISIBLE_KEYS"]
