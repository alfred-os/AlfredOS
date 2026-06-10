"""Config-sourced comms-adapter plugin-LOAD grants (ADR-0027, PR-S4-11b).

ADR-0026 seeds AlfredOS's OWN static defence (the system-tier
``security.quarantined.extract`` DLP subscriber) at boot. This module is its
config-sourced sibling: ONE plugin-LOAD grant per operator-enabled
FIRST-PARTY comms adapter, so the adapter's manifest-tier handshake
(:meth:`alfred.security.capability_gate.policy.GatePolicy.check_plugin_load`)
clears at boot.

Why this is NOT a fail-open / NOT the proposal flow
---------------------------------------------------
**Config-is-authorization for FIRST-PARTY adapters.** Every entry in
``Settings.comms_enabled_adapters`` is validated at construction
(:meth:`alfred.config.settings.Settings._validate_comms_enabled_adapters`)
to (a) match a path-safe charset and (b) name a real in-repo
``plugins/<id>/manifest.toml``. The enabled adapters are therefore all
first-party, source-controlled code the operator explicitly opted into via
reviewer-gated deployment config. Seeding their load grant at boot is the
exact parallel of ADR-0026's static DLP seed — a source-controlled
first-party defence, NOT the operator/reviewer proposal flow (which is not
projected into Postgres at boot anyway, and routing a config-declared
adapter through it would be circular in the same way ADR-0026 describes).

The gate stays a PURE grant evaluator: this module lands a real
:class:`GrantRow` row that the same hot-path
:meth:`alfred.security.capability_gate.policy.GatePolicy.check` evaluates.
:meth:`check_plugin_load` is NOT special-cased to "trust first-party by
name" — the adversarial corpus (``cap-2026-003``) pins that a non-enabled
plugin id is denied. The sandbox, DLP, and T3 boundary all still apply at
runtime; this grant ONLY clears the manifest-tier handshake for an adapter
the operator explicitly enabled.

Third-party / agent-authored adapters are OUT OF SCOPE for this cut: they
would route through the reviewer-gate proposal flow, never this seed.

Tier ceiling (FIX 1)
--------------------
The seed copies the manifest ``subscriber_tier`` VERBATIM into the wildcard
:class:`GrantRow`, so the config-is-authorization reasoning above only holds for
the postures it was written around: ``operator`` and ``user-plugin``. A comms
adapter is one of those two BY CONSTRUCTION. A manifest declaring
``subscriber_tier="system"`` would otherwise auto-receive a ``system``-tier
wildcard load grant from config alone — a self-escalation to the OS trust tier
riding the boot seed. The builder REFUSES it
(:class:`alfred.plugins.errors.CommsAdapterSystemTierError`, a
:class:`ManifestError` subclass) so the daemon boot maps it to the audited
``boot_infra_install_failed`` refusal (adversarial corpus ``cap-2026-004``).

Fail-closed
-----------
The Settings validator guarantees the manifest FILE exists, but not that it
parses. A broken/missing manifest at this builder raises
(:class:`alfred.plugins.errors.ManifestError` /
:class:`FileNotFoundError`) so a corrupt manifest REFUSES boot rather than
silently dropping the grant for an adapter the operator believes is enabled
(CLAUDE.md hard rule #7 — no silent failures in security paths). The builder
never returns a short tuple that omits an enabled adapter's grant.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

from alfred.plugins.errors import CommsAdapterSystemTierError
from alfred.plugins.manifest import parse_manifest
from alfred.security.capability_gate.policy import GrantRow

if TYPE_CHECKING:
    from alfred.config.settings import Settings

# The tier ceiling for a config-seeded comms-adapter LOAD grant (FIX 1). A
# comms adapter is ``operator`` or ``user-plugin`` BY CONSTRUCTION — both are
# postures the ADR-0027 config-is-authorization reasoning covers. ``system`` is
# NOT a comms-adapter posture: seeding a ``system``-tier wildcard load grant
# from config alone would be a self-escalation to the OS trust tier riding the
# boot seed, so the builder REFUSES it (CLAUDE.md hard rule #7).
_FORBIDDEN_COMMS_ADAPTER_TIER: Final[str] = "system"

# Resolve the repo root the same way ``Settings`` does (``parents[3]`` lands
# on the repo root from ``src/alfred/security/capability_gate/``). The
# comms-adapter manifests live at ``plugins/<id>/manifest.toml`` — the SAME
# location the ``comms_enabled_adapters`` validator probes, so the builder
# reads exactly the file the validator proved exists.
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]

# The state.git ``proposal_branch`` sentinel for a config-sourced
# comms-adapter load grant. DISTINCT from ADR-0026's
# ``bootstrap:first-party-system`` (the static DLP seed) so an audit-graph
# traversal can tell a config-sourced comms-adapter load grant apart from
# both the static first-party defence AND any operator/reviewer proposal
# grant. The ``"*"`` wildcard hookpoint matches every hookpoint at the
# adapter's manifest tier — the plugin-load grant shape (spec §8.2).
_COMMS_ADAPTER_PROPOSAL_BRANCH: Final[str] = "bootstrap:first-party-comms-adapter"


def comms_adapter_load_grants(settings: Settings) -> tuple[GrantRow, ...]:
    """Derive the boot plugin-LOAD grants for every enabled comms adapter.

    Pure ``Settings -> tuple[GrantRow, ...]`` transform: reads each enabled
    adapter's source-controlled manifest, derives the manifest ``[plugin]
    id`` (the launcher plugin id the handshake's
    :meth:`GatePolicy.check_plugin_load` queries) + its declared
    ``subscriber_tier``, and builds a wildcard plugin-LOAD
    :class:`GrantRow`.

    Returns ``()`` for the default-empty ``comms_enabled_adapters`` (a
    default daemon boot seeds only the static first-party grants). One grant
    per enabled adapter, in enumeration order, so the per-row seed/audit
    sequence is deterministic across boots.

    Raises:
        alfred.plugins.errors.CommsAdapterSystemTierError: An enabled adapter's
            manifest declares ``subscriber_tier="system"`` (FIX 1). A comms
            adapter is ``operator`` or ``user-plugin`` by construction;
            ``system`` is not a comms-adapter posture, so seeding a
            ``system``-tier wildcard load grant from config alone would be a
            self-escalation riding the boot seed. Refused fail-closed. The leaf
            subclasses :class:`ManifestError`, so the daemon's boot ``except``
            maps it to the audited ``boot_infra_install_failed`` refusal.
        alfred.plugins.errors.ManifestError: An enabled adapter's manifest
            does not parse (corrupt TOML, missing required field, bad tier).
            Surfaced loudly so a broken manifest REFUSES boot rather than
            silently dropping the grant (CLAUDE.md hard rule #7).
        FileNotFoundError / OSError: The manifest file is unreadable at the
            builder's repo root. Also surfaced loudly — never a silent skip.
    """
    grants: list[GrantRow] = []
    for adapter_id in settings.comms_enabled_adapters:
        manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
        # Loud on a missing/unreadable file — the Settings validator proved
        # the file existed at construction, but the builder must never seed
        # nothing-and-continue if it cannot read it.
        raw = manifest_path.read_text(encoding="utf-8")
        manifest = parse_manifest(raw)
        # FIX 1 — tier ceiling: a comms adapter is operator/user-plugin by
        # construction. A manifest declaring ``system`` would self-escalate to
        # the OS trust tier via a config-seeded wildcard grant; refuse it.
        if manifest.subscriber_tier == _FORBIDDEN_COMMS_ADAPTER_TIER:
            raise CommsAdapterSystemTierError(adapter_id)
        grants.append(
            GrantRow(
                plugin_id=manifest.plugin_id,
                subscriber_tier=manifest.subscriber_tier,
                hookpoint="*",
                content_tier=None,
                proposal_branch=_COMMS_ADAPTER_PROPOSAL_BRANCH,
            )
        )
    return tuple(grants)


__all__ = ["comms_adapter_load_grants"]
