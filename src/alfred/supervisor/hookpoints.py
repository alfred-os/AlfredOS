"""Boot-declarable hookpoint publisher for the supervisor (#443 PR1).

Extracted from ``Supervisor._register_hookpoints`` so the supervisor satisfies
``alfred.hooks.boot._declare_all_subsystem_hookpoints``'s stated obligation
(``boot.py:76-79``): every in-tree publisher MUST register there so its hookpoints
are declarable at boot. The supervisor was absent because its declaration was a
METHOD ON A CLASS, reachable only by constructing a ``Supervisor`` — making
``supervisor.plugin.sandbox_refused`` the only ``fail_closed=True`` security
hookpoint in the tree that a boot-time caller cannot declare.

That is harmless today (core-001 is moot for the current call site — ADR-0051:81-89;
the dispatch happens at first extraction, post-``Supervisor``). It becomes fatal at
#443 PR2, whose in-spawn handshake dispatches 125 lines BEFORE ``Supervisor(...)``:
under ``strict_declarations`` that raises ``HookError``, which the caller demotes to
a log line, so the fail-closed T0 hookpoint would never fire. #444 is blocked on the
same fix.

**No module-bottom ``declare_hookpoints()`` call — deliberately.** core-010
rejected import-time registration for these hookpoints: pytest collects every
test module's imports before any fixture runs, so the metadata would persist
across tests expecting a clean registry. The boot seam calls this explicitly
instead. Do not "fix" the omission — all nine other publishers have a
module-bottom call and the supervisor deliberately does not.

**The tuple is function-local on purpose.** ``test_known_hookpoints_sync.py``'s AST
drift resolver only resolves the inline ``hookpoints = (...)``-then-``for`` shape;
hoisting it to a module constant makes the resolver silently skip this module, and
the AST resolver's supervisor coverage drops to zero. (The dynamic sync test in the
same file still calls ``declare_hookpoints()`` directly and diffs the runtime
registry both ways, so it would still catch supervisor drift either hoisted or not —
this loss is specific to the independent static check.)

``Supervisor._register_hookpoints`` delegates here — one definition, two callers.
"""

from __future__ import annotations

from alfred.hooks import SYSTEM_ONLY_TIERS, SYSTEM_OPERATOR_TIERS, HookRegistry, get_registry
from alfred.security.tiers import T0, TrustTier


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register every supervisor hookpoint.

    Idempotent on equal metadata, strict on drift, so the boot seam and
    ``Supervisor.__init__`` may both call it.

    Args:
        registry: Optional override; defaults to the active singleton.
    """
    target = get_registry() if registry is None else registry
    # Per-hookpoint trust-tier rationale:
    #
    # * ``supervisor.breaker.tripped`` — system-only emission of an
    #   internal state-machine transition; user-plugin subscribers
    #   would be a security smell (they'd see when the quarantine
    #   fires) and operator subscribers add nothing the audit-graph
    #   dashboards don't already surface. ``fail_closed=False``: a
    #   crashing subscriber on this event is observability noise,
    #   not a security regression — the breaker transition itself
    #   is persisted to Postgres irrespective of the hook chain.
    # * ``supervisor.breaker.reset`` — operator-triggered command
    #   (spec §10.8). System + operator tiers may subscribe (operator
    #   for CLI confirmation flow, system for audit forwarding);
    #   user-plugin locked out. ``fail_closed=False`` for the same
    #   reason as ``.tripped``.
    # * ``supervisor.action_timeout`` — system-only emission from the
    #   orchestrator's ``DeadlineWrapper`` arm (core-003). Same
    #   posture as ``.tripped``.
    # * ``plugin.lifecycle.{loaded,crashed,quarantined}`` — three
    #   system-only emissions covering the spec §10.3 lifecycle.
    #   ``fail_closed=False`` consistent with the rest of the
    #   supervisor's observability-shaped hookpoints.
    #
    # PR-S4-3: every supervisor hookpoint is system-internal
    # observability (breaker state transitions, action-timeout
    # signals, plugin-lifecycle events). T0 (system-only) is the
    # correct carrier tier upper bound — none of these paths
    # carries operator or untrusted content.
    hookpoints: tuple[tuple[str, frozenset[str], frozenset[str], bool, type[TrustTier]], ...] = (
        ("supervisor.breaker.tripped", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        ("supervisor.breaker.reset", SYSTEM_OPERATOR_TIERS, frozenset(), False, T0),
        ("supervisor.action_timeout", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        ("plugin.lifecycle.loaded", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        ("plugin.lifecycle.crashed", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        ("plugin.lifecycle.quarantined", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        # PR-S4-6 (ADR-0015) sandbox-launcher hookpoints. All T0 —
        # system-internal posture/refusal signals carrying only
        # plugin_id + closed-vocabulary reason (no operator/untrusted
        # content). sandbox_refused is fail_closed (a subscriber-timeout
        # there must not let a refused spawn slip through); the two boot
        # posture rows are informational (fail_closed=False — boot
        # proceeds even when mlockall is unavailable or a subscriber is
        # slow).
        ("supervisor.plugin.sandbox_refused", SYSTEM_ONLY_TIERS, frozenset(), True, T0),
        # PR-S4-7: the dev/test-only stub-used row. The launcher emits this
        # (and execs unsandboxed) ONLY in development/test when no real OS
        # sandbox is available. Three producers, all in
        # bin/alfred-plugin-launcher.sh: a non-Linux host with no UID-drop
        # mechanism (uid_separation_unavailable), a Windows kind:full
        # manifest (windows_stub), and a kind:stub manifest (stub_kind).
        # The runuser-missing-on-Linux path is NOT one of these — it
        # always refuses pre-exec (reason=runuser_unavailable, a
        # sandbox_refused row, wired by #435) and never reaches this
        # hookpoint.
        #
        # Registered + declared here, but UNPUBLISHED: no code path calls
        # invoke() for this hookpoint (contrast sandbox_refused, dispatched
        # by alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor).
        # Persistence is deliberately NOT wired (#436 / ADR-0051): this row
        # asserts "I am about to exec", so a live child shares the
        # launcher's stderr fd with no delimiter between launcher-authored
        # and child-authored bytes — the existing drain gate
        # (quarantine_child_io._SubprocessChildIO's `refusal_candidate and
        # not self._child_wrote_stdout`) is an INVERTED oracle for it: an
        # honest child that execs writes stdout and closes the gate
        # (discarding the true row), while a forging child that writes
        # zero stdout before dying OPENS it. Persisting this row for real
        # needs a success-path stderr drain with its own out-of-band
        # provenance signal — tracked as #447.
        #
        # carrier_tier=T0 (carries only plugin_id/policy_ref/host_os/
        # environment/reason — no operator/untrusted content; spec index
        # §3). fail_closed=True, mirroring its sandbox_refused sibling
        # verbatim (#167 per-kind override deferred — all Slice-4
        # supervisor refusal/posture hookpoints are uniformly fail-closed).
        ("supervisor.plugin.sandbox_stub_used", SYSTEM_ONLY_TIERS, frozenset(), True, T0),
        ("supervisor.boot.mlock_unavailable", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        ("supervisor.boot.core_dumps_disabled", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
    )
    for name, subscribable_tiers, refusable_tiers, fail_closed, carrier_tier in hookpoints:
        target.register_hookpoint(
            name=name,
            subscribable_tiers=subscribable_tiers,
            refusable_tiers=refusable_tiers,
            fail_closed=fail_closed,
            carrier_tier=carrier_tier,
        )


__all__ = ["declare_hookpoints"]
