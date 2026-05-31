"""Pure capability-gate policy matching — no I/O, no env reads, no globals.

Spec §8.1 (Fork 7): grant policy is derived from the state.git
``policies/grants/`` tree and projected into the Postgres
``plugin_grants`` table. :class:`GatePolicy` is the in-memory snapshot
above the Postgres read; hot-path :meth:`RealGate.check` dispatches
through this layer and never reaches the database on the fast path.

Hard invariants pinned by ``tests/unit/security/capability_gate/test_gate_policy.py``:

* **sec-007 extension** — this module does NOT ``import os``. No env
  reads, no path lookups, no environment-dependent grant decisions. DSN
  selection and ALFRED_ENV lookup live in
  :mod:`alfred.bootstrap.gate_factory` (forthcoming PR-S3-2 task).
* **Frozen rows** — :class:`GrantRow` is a frozen dataclass; the
  snapshot cannot be tampered with at runtime (CLAUDE.md hard rule #4
  spirit — bypass-impossible).
* **Empty-grants always denies** — :class:`GatePolicy` with no grants
  denies every check method (CLAUDE.md hard rule #7 fail-closed
  default; also the bootstrap state before
  :meth:`RealGate._apply_grants` lands the first real snapshot).
* **Two-axis naming rule (spec §4.3)** — the field is named
  ``subscriber_tier`` not ``tier`` so the subscriber-capability axis
  (``system`` / ``operator`` / ``user-plugin``) is never confused with
  the orthogonal content trust tier (``T0`` / ``T1`` / ``T2`` / ``T3``).
  Both axes are exposed as separate fields on :class:`GrantRow` and
  matched independently.

The matching algorithm is intentionally O(n) over the grant set — the
expected n is small (low hundreds for a busy deployment), and any
indexed structure would require mutation on rebuild that the frozen
snapshot semantics forbid. If grant counts ever grow, a future PR can
introduce an indexed projection without changing the public surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GrantRow:
    """A single capability grant row read from the ``plugin_grants`` table.

    Mirrors the row schema declared in migration ``0008_plugin_grants``
    (PR-S3-0b). Frozen so a snapshot held by :class:`GatePolicy` cannot
    be tampered with at runtime — the bypass-impossible posture mirrors
    :class:`alfred.hooks.capability.DevGate`'s frozen dataclass shape.

    Fields:

    * ``plugin_id`` — MCP plugin identifier (e.g.
      ``"alfred.quarantined-llm"``).
    * ``subscriber_tier`` — closed domain
      ``{"system", "operator", "user-plugin"}``. The
      subscriber-capability axis (spec §4.3) — NOT a content trust tier.
    * ``hookpoint`` — dotted action name (e.g.
      ``"tool.web.fetch"``) or ``"*"`` for a wildcard grant covering
      every hookpoint at that (plugin_id, subscriber_tier) pair.
    * ``content_tier`` — orthogonal trust tier the grant clears
      (``"T0"`` / ``"T1"`` / ``"T2"`` / ``"T3"``) or ``None`` for
      subscriber-tier-only grants. ``None`` means "no content-tier
      restriction".
    * ``proposal_branch`` — state.git branch name (e.g.
      ``"proposal/policy-grant-abc"``) that produced this grant; threaded
      through for audit-graph linkage (spec §8.5).
    """

    plugin_id: str
    subscriber_tier: str
    hookpoint: str
    content_tier: str | None
    proposal_branch: str


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Immutable in-memory snapshot of all active grants.

    Built from the ``plugin_grants`` Postgres table on startup and after
    any state.git commit-hash change. Replaced atomically on rebuild
    (:meth:`RealGate._apply_grants` assigns a new instance under the
    single-threaded asyncio event loop) — never mutated in place.

    The default-constructed empty snapshot is the safe bootstrap state:
    every check method returns ``False`` until at least one
    :meth:`RealGate._apply_grants` has landed.
    """

    grants: frozenset[GrantRow] = field(default_factory=frozenset)

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool:
        """Return ``True`` iff a grant matches the (plugin_id, hookpoint, tier) triple.

        Wildcard semantics: a grant with ``hookpoint="*"`` matches any
        hookpoint string for the matching ``(plugin_id, subscriber_tier)``
        pair. Used by plugin-load grants where the operator wants to
        clear every hookpoint at once.

        Returns ``False`` on the empty-grants snapshot and on any
        mismatch — spec §8.1 fail-closed default.
        """
        for grant in self.grants:
            if grant.plugin_id != plugin_id:
                continue
            if grant.subscriber_tier != requested_tier:
                continue
            if grant.hookpoint == "*" or grant.hookpoint == hookpoint:
                return True
        return False

    def check_plugin_load(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
    ) -> bool:
        """Gate plugin load at handshake time (spec §8.2).

        Delegates to :meth:`check` with ``hookpoint="*"`` because a
        plugin-load grant covers every hookpoint at the matching
        subscriber_tier. ``manifest_tier`` is the
        subscriber-capability axis the plugin's manifest declares;
        a ``system`` plugin must hold a ``system``-tier grant.
        """
        return self.check(
            plugin_id=plugin_id,
            hookpoint="*",
            requested_tier=manifest_tier,
        )

    def check_content_clearance(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        content_tier: str,
    ) -> bool:
        """Gate content-tier access on the orthogonal trust axis (spec §8.2).

        Matching is exact on ``content_tier`` — a ``T3`` grant does not
        clear ``T2`` content (and vice versa). Wildcard ``hookpoint="*"``
        semantics match :meth:`check`: a single wildcard row clears the
        plugin for every hookpoint at the matching ``content_tier``.

        The subscriber_tier axis is NOT consulted here — content_tier
        and subscriber_tier are independent (spec §4.3). A plugin can
        hold a subscriber-tier grant without content-tier clearance and
        vice versa.
        """
        for grant in self.grants:
            if grant.plugin_id != plugin_id:
                continue
            if grant.content_tier != content_tier:
                continue
            if grant.hookpoint == "*" or grant.hookpoint == hookpoint:
                return True
        return False
