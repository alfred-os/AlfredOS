"""Plugin error hierarchy (spec §4, ADR-0017 Decision 6).

The hierarchy keeps three orthogonal failure axes distinct so audit-log
consumers can branch on a single ``except`` and so the orchestrator can
react differently to manifest rejection vs DLP refusal vs subprocess
crash:

* ``ManifestError`` — every reason a manifest is refused at handshake.
  Subclasses: ``ManifestVersionError`` (wrong ``alfred.manifest_version``)
  and ``ManifestTierError`` (T0-T3 supplied as ``subscriber_tier``).
* ``PluginTransportError`` — every wire-level failure post-handshake.
  Subclasses: ``PluginProtocolViolation`` (disallowed JSON-RPC method) and
  ``DlpOutboundRefusedError`` (DLP refused an outbound frame).
* ``PluginInvocationError`` — a plugin RPC returned an error response that
  is not a transport-level failure (the plugin itself failed to satisfy
  the call). Carried separately so transport-level retry/back-off logic
  doesn't fire on an application-level failure.
* ``QuarantinedUnavailable`` — the quarantined LLM subprocess is not
  reachable. Lives here per ADR-0017 Decision 6; supervisor re-exports
  for ergonomic import in PR-S3-3b.

Every leaf descends from :class:`PluginError`, which descends from
:class:`alfred.errors.AlfredError` so the CLI top-level dispatch and
orchestrator catch arms catch them uniformly. Leaves carry the structured
attributes the audit log depends on (``plugin_id``, ``method``,
``rule_matched``, etc.) — these attributes are part of the public
contract and tested.

These are operational errors only. They MUST NOT carry T3 content (spec
§5.6 audit-field discipline): plugin id, method name, rule name, version
integers, and tier strings are all safe; raw bytes from the plugin are
not. Constructor signatures are designed so this rule is hard to violate.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t

# ---------------------------------------------------------------------------
# Root + intermediate parents.
# ---------------------------------------------------------------------------


class PluginError(AlfredError):
    """Root for every plugin-domain error.

    Descends from :class:`alfred.errors.AlfredError` so the CLI top-level
    dispatch catches the whole family uniformly without swallowing
    unrelated exceptions.
    """


class ManifestError(PluginError):
    """A plugin manifest was rejected at handshake.

    Catch this to handle every manifest-rejection shape without listing
    each leaf.
    """


class PluginTransportError(PluginError):
    """A wire-level transport failure (post-handshake).

    Catch this to handle every transport-level failure shape (protocol
    violation, DLP refusal, etc.) without listing each leaf.
    """


class PluginInvocationError(PluginError):
    """The plugin returned an error response for a JSON-RPC call.

    Distinct from :class:`PluginTransportError` — the wire was healthy but
    the plugin itself failed to satisfy the call. Carried separately so
    transport-level retry logic does not fire on an application-level
    failure.
    """

    def __init__(self, method: str, detail: str) -> None:
        super().__init__(t("plugin.invocation_failed", method=repr(method), detail=detail))
        self.method = method
        self.detail = detail


# ---------------------------------------------------------------------------
# QuarantinedUnavailable — ADR-0017 Decision 6: definition lives here,
# supervisor re-exports.
# ---------------------------------------------------------------------------


class QuarantinedUnavailable(PluginError):  # noqa: N818 -- name pinned by ADR-0017 Decision 6 + spec §5.5
    """The quarantined LLM subprocess is unreachable.

    Raised by the plugin transport when a ``quarantine.extract`` call cannot
    be dispatched (subprocess crashed, capacity exhausted, supervisor
    declines to spawn a fresh worker). Spec §5.5 says this is a "distinct
    top-level exception" in this module; ADR-0017 Decision 6 resolves the
    spec §10.1 contradiction in favour of this location.

    ``reason`` is a free-form string for operator forensics; it MUST NOT
    contain T3 content. Spec §5.6.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(t("plugin.quarantined_unavailable", reason=reason))
        self.reason = reason


# ---------------------------------------------------------------------------
# Manifest leaves.
# ---------------------------------------------------------------------------


class ManifestVersionError(ManifestError):
    """``alfred.manifest_version`` does not equal the expected version.

    Slice-3 pins the expected version to 1 (ADR-0017 Decision 7). Any other
    value is refused at the handshake before any capability-gate check
    runs.

    ``got`` and ``expected`` are integers and safe to carry in audit rows.
    """

    def __init__(self, got: int, expected: int = 1) -> None:
        # ``t()`` returns the key itself when no catalog entry matches, so
        # this is safe to call before the catalog ships the entry. Once the
        # entry lands, this becomes a localised message; the structured
        # attributes (``got``/``expected``) remain the audit-log contract.
        super().__init__(t("plugin.manifest_version_mismatch", got=got, expected=expected))
        self.got = got
        self.expected = expected


class ManifestSandboxMissingError(ManifestError):
    """The manifest lacks a required ``[sandbox]`` block (spec §7.1, PR-S4-6).

    Distinct leaf from the generic :class:`ManifestError` so the
    supervisor's ``supervisor.plugin.sandbox_refused`` emit can attribute
    ``reason="sandbox_block_missing"`` from the exception *type* without
    parsing the message string. A plugin with no declared isolation posture
    must never load — the parser fails closed (CLAUDE.md hard rule #7).

    ``plugin_id`` is the manifest-declared id (a closed-vocabulary slug) and
    is safe to carry in audit rows (spec §5.6).
    """

    def __init__(self, plugin_id: str) -> None:
        super().__init__(t("plugin.manifest_sandbox_block_missing", plugin_id=plugin_id))
        self.plugin_id = plugin_id


class ManifestTierError(ManifestError):
    """The manifest declared a content trust tier (T0-T3) as ``subscriber_tier``.

    Uses a dedicated i18n key (``plugin.manifest_subscriber_tier_invalid``)
    distinct from the version-mismatch key — arch-007 fix. The two errors
    have different numeric/string formatting semantics across languages.

    ``tier`` is the raw value supplied in the manifest (a string from a
    closed vocabulary, T0/T1/T2/T3) and is safe to carry in audit rows.
    """

    def __init__(self, tier: str) -> None:
        super().__init__(
            t(
                "plugin.manifest_subscriber_tier_invalid",
                tier=tier,
                valid_tiers="system|operator|user-plugin",
            )
        )
        self.tier = tier


class CommsAdapterSystemTierError(ManifestError):
    """An enabled comms adapter's manifest declares ``subscriber_tier="system"``.

    FIX 1 (PR-S4-11b review BLOCKER): the config-sourced comms-adapter LOAD
    grant (ADR-0027 Decision 6) copies the manifest ``subscriber_tier`` into a
    seeded wildcard :class:`GrantRow`. ``config-is-authorization`` was reasoned
    around ``operator`` / ``user-plugin`` adapters; a comms manifest declaring
    ``system`` would otherwise auto-receive a ``system``-tier wildcard load
    grant from config alone — a self-escalation to the OS trust tier riding the
    boot seed. A comms adapter is ``operator`` or ``user-plugin`` BY
    CONSTRUCTION; ``system`` is not a comms-adapter posture, so the
    grants-builder fails closed (CLAUDE.md hard rule #7) with this dedicated
    leaf. Subclasses :class:`ManifestError` so the daemon's boot ``except``
    maps it to the audited ``boot_infra_install_failed`` refusal rather than a
    raw traceback.

    ``adapter_id`` is the operator-config adapter id (charset-validated by the
    ``comms_enabled_adapters`` Settings field) and is safe in audit rows.
    """

    def __init__(self, adapter_id: str) -> None:
        super().__init__(t("plugin.comms_adapter_system_tier_refused", adapter_id=adapter_id))
        self.adapter_id = adapter_id


# ---------------------------------------------------------------------------
# Transport leaves.
# ---------------------------------------------------------------------------


class PluginProtocolViolation(PluginTransportError):  # noqa: N818 -- name pinned by spec §4.6
    """The plugin sent a disallowed JSON-RPC method post-handshake.

    Concrete trigger in Slice 3: an ``alfred/hooks.register`` frame after
    the handshake completed (only the host registers hooks; a plugin
    asking to register one is a quarantine trigger — spec §4.6).

    ``method`` is the JSON-RPC method name (a closed-vocabulary string)
    and ``plugin_id`` is the manifest-declared id. Both are safe in audit
    rows.
    """

    def __init__(self, method: str, plugin_id: str) -> None:
        super().__init__(t("plugin.protocol_violation", plugin_id=plugin_id, method=repr(method)))
        self.method = method
        self.plugin_id = plugin_id


class SandboxInfoHandshakeMismatch(PluginTransportError):  # noqa: N818 -- name pinned by PR-S4-6 arch-3
    """A plugin's reported sandbox posture disagrees with its manifest (arch-3).

    After the handshake a plugin may attest its effective isolation via a
    ``sandbox_info`` method. If the reported ``effective_sandbox_kind`` does
    not match the manifest's declared ``sandbox.kind`` — a plugin lying about
    its own containment — the Supervisor tears down the session.

    ``declared`` (manifest kind) and ``reported`` (plugin-attested kind) are
    closed-vocabulary strings safe to carry in audit rows.
    """

    def __init__(self, plugin_id: str, declared: str, reported: str) -> None:
        super().__init__(
            t(
                "supervisor.sandbox.refused.sandbox_info_handshake_mismatch",
                plugin_id=plugin_id,
                declared=declared,
                reported=reported,
            )
        )
        self.plugin_id = plugin_id
        self.declared = declared
        self.reported = reported


class DlpOutboundRefusedError(PluginTransportError):
    """:class:`alfred.security.dlp.OutboundDlp` refused an outbound frame.

    Distinct leaf so operators reading audit logs can tell DLP refusals
    apart from sandbox-policy failures and manifest rejections
    (arch-006 / err-011 fix).

    ``rule_matched`` is the DLP rule identifier (closed vocabulary) and
    ``plugin_id`` is the manifest-declared id. Both are safe in audit
    rows; the matched bytes themselves MUST NOT be passed in here.
    """

    def __init__(self, plugin_id: str, rule_matched: str) -> None:
        super().__init__(
            t("plugin.transport.dlp_outbound_refused", plugin_id=plugin_id, rule=rule_matched)
        )
        self.plugin_id = plugin_id
        self.rule_matched = rule_matched


__all__ = [
    "DlpOutboundRefusedError",
    "ManifestError",
    "ManifestSandboxMissingError",
    "ManifestTierError",
    "ManifestVersionError",
    "PluginError",
    "PluginInvocationError",
    "PluginProtocolViolation",
    "PluginTransportError",
    "QuarantinedUnavailable",
    "SandboxInfoHandshakeMismatch",
]
