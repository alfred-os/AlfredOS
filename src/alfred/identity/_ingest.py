"""Ingress trust-tier derivation - role x adapter classification.

This module owns the ONLY legitimate place where raw identity +
adapter metadata is translated into a TrustTier for a user's message.
It lives in alfred.identity (NOT in alfred.orchestrator.core) because
the orchestrator's invariant is that input arrives already-tagged at
its boundary - placing this logic in core.py would violate that.

Reserved — no live caller post-PR-S4-10 (#206); see issue #237. Before the
comms-MCP flag-day each in-process CommsAdapter called :func:`_ingest_tier`
at its ingress boundary. After the flag-day deleted ``src/alfred/comms``,
ingress trust-tier tagging is owned host-side by
:mod:`alfred.comms_mcp.inbound` (T3 at the quarantine boundary). This module
is retained for its hookpoint-declaration side effect (see
:func:`declare_hookpoints`); the PR-S3-4 dual-LLM-split work will wire the
``_ingest_tier`` invoke site. The function currently has unit coverage but
NO production call path — do not describe it as live-invoked.

Rule (spec §3.6) — keyed on the ``adapter_id`` KIND prefix (PR-S4-10):

- TUI + operator role -> T1 (operator tier: highest-trust, TUI only)
- Discord + operator role -> T2 (Discord is broadcast-shaped, never T1)
- Any role + any adapter -> T2 otherwise (safe default)

T1 outbound channel is TUI stdout only in Slice 3.
The ``.authorization`` field on User is a ``Mapped[str]`` column - compare
against ``Authorization.OPERATOR.value`` (a str), not the enum itself,
per resolver.py:183 comment and the existing usage pattern.

Hookpoint registration (spec §14):

This module is the publisher for ``identity.t1_ingress`` and
``identity.t1_downgrade``. Per spec §6.2 (publishers declare at module
import time), :func:`declare_hookpoints` is called at the bottom of
this file against the active :class:`alfred.hooks.HookRegistry`
singleton so subscribers can register against the dotted names from
PR-S3-4 onward.

The declarations are STUBS in this PR — no ``invoke()`` call site lands
in PR-S3-1. The full ingress-time post-hook emission (carrying the
:data:`alfred.security.audit_row_schemas.T1_INGRESS_FIELDS` row) lands
in PR-S3-4 alongside the dual-LLM split work; declaring the hookpoints
here lets that PR wire the invoke site without an additional
declaration cycle.

See ADR-0017, spec §3.6 (role-adapter derivation), §14 (hookpoint
table — both ``identity.t1_*`` hookpoints use
``subscribable_tiers=SYSTEM_OPERATOR_TIERS``, no refusable tiers, and
``fail_closed=False``).
"""

from __future__ import annotations

from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS, HookRegistry, get_registry
from alfred.identity.models import Authorization
from alfred.security.tiers import T1, T2, TrustTier

# Centralised hookpoint identifiers — declaration and (PR-S3-4) invoke
# sites pin to the same constant so a typo on either side surfaces as a
# register-time strict-declaration failure under #119. Mirrors the
# Slice-2.5 :mod:`alfred.memory.episodic` precedent.
HOOKPOINT_T1_INGRESS: str = "identity.t1_ingress"
HOOKPOINT_T1_DOWNGRADE: str = "identity.t1_downgrade"


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Declare ``identity.t1_ingress`` and ``identity.t1_downgrade`` (spec §14).

    Idempotent — re-running this against the same registry is a no-op
    (``HookRegistry.register_hookpoint`` is idempotent on equal metadata).
    That property makes the dual call discipline from the
    :mod:`alfred.memory.episodic` precedent safe:

    * **Module-init** (called at the bottom of this file) — the
      production path. The first ``from alfred.identity._ingest import
      _ingest_tier`` triggers the declaration against the global
      singleton; subscribers registered against either name resolve.
    * **Per-call** (currently not wired — PR-S3-4 will add a call from
      whichever module owns the ingest invoke site) — the test path.
      A fixture that swaps :func:`get_registry`'s singleton with a
      fresh registry sees the declaration land on whichever registry
      is active when the invoke site runs.

    Args:
        registry: The :class:`HookRegistry` to declare against. Defaults
            to :func:`get_registry`'s active singleton; tests pass the
            fresh registry explicitly to be unambiguous.
    """
    target = registry if registry is not None else get_registry()
    # Both hookpoints — post-only emission, system + operator subscribers
    # only (a user-plugin watcher of T1 traffic would defeat the
    # broadcast-shape contract), no refusal authorized (T1 ingress is
    # an observability stage, not a security gate), and ``fail_closed=
    # False`` because a crashing observer must not stall the ingest path.
    # Tier sets match spec §14 verbatim.
    target.register_hookpoint(
        name=HOOKPOINT_T1_INGRESS,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        # PR-S4-3: T1 carrier (operator-tier ingress per spec §14).
        carrier_tier=T1,
    )
    target.register_hookpoint(
        name=HOOKPOINT_T1_DOWNGRADE,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T1,
    )


def _ingest_tier(user: object, adapter_id: str) -> type[TrustTier]:
    """Derive ingress trust tier from the role x adapter-kind pair.

    Args:
        user: Any object with an ``authorization`` attribute (``Mapped[str]``).
            Typically :class:`alfred.identity.models.User`; typed as ``object``
            here to avoid circular imports at the identity boundary.
        adapter_id: The per-instance comms-MCP adapter id carried on the wire
            (e.g. ``"tui-9f3c2b1e"``, ``"discord-bot-prod"``). The
            adapter-KIND prefix is the contract — ``"tui*"`` is the TUI
            kind, ``"discord*"`` is the Discord kind.

    Returns:
        ``T1`` for the TUI kind + operator role; ``T2`` for all other
        combinations.

    Spec §3.6 is explicit: Discord is broadcast-shaped and never T1 even
    for operator-role users. This invariant is hard-coded here rather than
    left to per-adapter configuration to prevent misconfiguration drift.

    PR-S4-10 (#206) migrated the parameter from ``adapter_name`` (the
    in-process ``CommsAdapter.name``, a bare kind like ``"tui"``) to
    ``adapter_id`` (the comms-MCP wire id, a per-instance value). The gate
    matches the TUI KIND as ``adapter_id == "tui"`` OR
    ``adapter_id.startswith("tui-")`` — the KIND is the segment before the
    first ``-`` separator. An UNANCHORED ``startswith("tui")`` (the original
    PR-S4-10 form) was a trust-escalation bug: it matched lookalike kinds
    like ``"tuide-evil"`` / ``"tui_discord"`` / ``"tuixyz"`` and granted them
    operator-tier T1 (review F5). The kwarg rename is a hard break — a stale
    ``adapter_name=`` caller raises ``TypeError`` rather than silently
    defaulting to T2.

    Reserved — no live caller post-PR-S4-10; see issue #237. After the
    comms-MCP flag-day the host tags ingress trust tiers in
    :mod:`alfred.comms_mcp.inbound` (T3 at the quarantine boundary), not via
    this role-x-adapter helper. The function is retained because its module
    import is the publisher side-effect for the ``identity.t1_*`` hookpoints
    (see :func:`declare_hookpoints`); the PR-S3-4 dual-LLM-split work will
    wire its invoke site. Until then it has unit coverage but no production
    call path.
    """
    authorization: str = getattr(user, "authorization", "")
    is_tui_kind = adapter_id == "tui" or adapter_id.startswith("tui-")
    if is_tui_kind and authorization == Authorization.OPERATOR.value:
        return T1
    return T2


# Module-init declaration — #119 / spec §6.2: publishers declare at
# import time. Idempotent on equal metadata so re-importing under pytest
# test-isolation is safe. The PR-S3-4 invoke site will additionally call
# :func:`declare_hookpoints` from whatever module owns the invoke path
# so a test fixture's fresh registry sees the declaration too — same
# discipline as :mod:`alfred.memory.episodic`.
declare_hookpoints()
