"""Audit-row schema + hookpoint declaration wiring for the grant lifecycle.

Two invariants under test:

1. **Schema coverage** — the three :mod:`alfred.audit.audit_row_schemas`
   constants relevant to the capability-gate grant family carry every
   field the spec §13 schema declares. A drift between the declared
   schema and the constant would silently let an emitter omit a field
   (the symmetric-key-set check in :meth:`AuditWriter.append_schema`
   catches that at write time, but the catch happens too late — we want
   the static guard at import time).
2. **Hookpoint declaration** — the four ``plugin.grant.*`` lifecycle
   hookpoints are declared by :mod:`alfred.security.capability_gate.proposals`
   at module-init time (mirrors the :mod:`alfred.identity._ingest` and
   :mod:`alfred.memory.episodic` precedents). The declarations use
   :data:`SYSTEM_ONLY_TIERS` because a user-plugin subscriber of
   ``plugin.grant.approved`` would see every operator grant approval —
   that is itself an exfiltration path (spec §14 hookpoint table
   classifies these as system-only observability stages).

Spec §8.1 also calls out ``supervisor.capability_gate_unavailable`` as
an audit event that is NOT a hookpoint (it is emitted directly through
:meth:`AuditWriter.append_schema` and never traverses the dispatcher —
hooking the audit emit through the dispatcher would be circular when the
backing store is itself unavailable). Task 17 documents that distinction
with the dedicated test below.
"""

from __future__ import annotations

import pytest

from alfred.audit.audit_row_schemas import (
    PLUGIN_GRANT_FIELDS,
    PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS,
    SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
)
from alfred.hooks.registry import HookRegistry
from alfred.security.capability_gate.proposals import (
    HOOKPOINT_GRANT_APPROVED,
    HOOKPOINT_GRANT_DENIED,
    HOOKPOINT_GRANT_REQUESTED,
    HOOKPOINT_GRANT_REVOKED,
    declare_hookpoints,
)
from tests.helpers.gates import make_permissive_fixture_gate

# ---------------------------------------------------------------------------
# Schema coverage tests (Task 16)
# ---------------------------------------------------------------------------


def test_plugin_grant_fields_carries_required_keys() -> None:
    """Spec §8.5 + §13: the grant-lifecycle row carries the canonical fields.

    A drift here (renaming ``operator_user_id`` to ``operator_id``, say)
    would let a forensic query lose its WHERE clause silently. The
    superset assertion lets the constant grow over time without
    breaking this test, while still failing loudly on drop / rename.
    """
    required = {
        "plugin_id",
        "subscriber_tier",
        "hookpoint",
        "operator_user_id",
        "proposal_branch",
        "correlation_id",
    }
    assert required <= PLUGIN_GRANT_FIELDS


def test_plugin_grant_revoked_inflight_fields_carries_required_keys() -> None:
    """Spec §13: in-flight revocation rows surface the dispatch id.

    The ``in_flight_dispatch_id`` field is what lets the forensic graph
    correlate a revoked grant back to the specific dispatch the
    revocation interrupted; without it, a revoke during dispatch is
    indistinguishable from a revoke between dispatches.
    """
    required = {
        "plugin_id",
        "hookpoint",
        "operator_user_id",
        "in_flight_dispatch_id",
        "correlation_id",
    }
    assert required <= PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS


# ---------------------------------------------------------------------------
# Hookpoint declaration tests (Task 16)
# ---------------------------------------------------------------------------


def test_declare_hookpoints_registers_all_four_grant_lifecycle_names() -> None:
    """All four ``plugin.grant.*`` names land in a fresh registry.

    Asserts the publisher-side contract: a process that imports
    :mod:`alfred.security.capability_gate.proposals` (or calls
    :func:`declare_hookpoints` against a fresh registry) sees the
    metadata for every lifecycle event. A subscriber registering
    against ``plugin.grant.denied`` before the declaration would face
    register_hookpoint's strict-declaration error.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    expected = {
        HOOKPOINT_GRANT_REQUESTED,
        HOOKPOINT_GRANT_APPROVED,
        HOOKPOINT_GRANT_DENIED,
        HOOKPOINT_GRANT_REVOKED,
    }
    for name in expected:
        # The public accessor returns the stored HookpointMeta or None
        # — anything other than None means register_hookpoint landed.
        assert registry.hookpoint_meta(name) is not None, (
            f"declare_hookpoints did not register {name!r}"
        )


def test_declare_hookpoints_uses_system_only_subscribable_tiers() -> None:
    """Subscriber tier must be system-only — spec §14.

    A user-plugin subscriber of ``plugin.grant.approved`` would witness
    every operator-approved grant, which is itself an exfiltration
    vector (spec §14 classifies these as system-only observability
    stages). Operator-tier subscribers are also locked out to keep the
    surface inside the supervisor process.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    for name in (
        HOOKPOINT_GRANT_REQUESTED,
        HOOKPOINT_GRANT_APPROVED,
        HOOKPOINT_GRANT_DENIED,
        HOOKPOINT_GRANT_REVOKED,
    ):
        meta = registry.hookpoint_meta(name)
        assert meta is not None, f"{name} missing from registry"
        assert meta.subscribable_tiers == frozenset({"system"}), (
            f"{name} declared with non-system tiers: {meta.subscribable_tiers}"
        )


def test_declare_hookpoints_uses_no_refusable_tiers() -> None:
    """No tier may refuse a grant-lifecycle event — spec §14.

    The lifecycle events are post-only observability stages; refusal
    semantics would race the reviewer-gate flow. A subscriber that
    needs to BLOCK a grant raises its concern through the proposal
    review, not the hook chain.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    for name in (
        HOOKPOINT_GRANT_REQUESTED,
        HOOKPOINT_GRANT_APPROVED,
        HOOKPOINT_GRANT_DENIED,
        HOOKPOINT_GRANT_REVOKED,
    ):
        meta = registry.hookpoint_meta(name)
        assert meta is not None, f"{name} missing from registry"
        assert meta.refusable_tiers == frozenset(), (
            f"{name} declared with refusable tiers: {meta.refusable_tiers}"
        )


def test_declare_hookpoints_fail_closed_is_false() -> None:
    """``plugin.grant.*`` hookpoints follow spec §14: ``fail_closed=False``.

    CR-149 round-3: spec §14's hookpoint table classifies every
    ``plugin.grant.*`` row as ``fail_closed=False``. The trust-boundary
    audit row that pins the reviewer's decision is emitted via the
    supervisor's :meth:`AuditWriter.append_schema` BEFORE the observer
    chain runs, so a crashing observer cannot hide the grant from the
    audit log — the row is already durable. Keeping the chain on
    ``fail_closed=False`` honours the spec contract and prevents an
    observer crash from stalling the privileged grant flow.

    The ``SYSTEM_ONLY_TIERS`` lock keeps user-plugin subscribers out
    of the chain entirely, so the availability / safety trade-off is
    bounded to system-tier observers regardless of this flag.

    The earlier sec-pr-s3-6-05 override (``fail_closed=True``) drifted
    from the spec table; round-3 reviewer pushed back and the
    implementation now follows the spec.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    for name in (
        HOOKPOINT_GRANT_REQUESTED,
        HOOKPOINT_GRANT_APPROVED,
        HOOKPOINT_GRANT_DENIED,
        HOOKPOINT_GRANT_REVOKED,
    ):
        meta = registry.hookpoint_meta(name)
        assert meta is not None, f"{name} missing from registry"
        assert meta.fail_closed is False, f"{name} declared fail_closed=True"


def test_declare_hookpoints_is_idempotent() -> None:
    """Re-calling against the same registry succeeds (equal-metadata rule).

    :meth:`HookRegistry.register_hookpoint` is idempotent on equal
    metadata; the proposals module's module-init declaration plus any
    per-call invocation (PR-S3-6's CLI may add one) must both succeed
    without raising. This test pins the contract so a future change
    that flips a meta field silently does not slip past — the second
    call would then raise.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    # Second call MUST NOT raise — equal metadata is the legal idempotent shape.
    declare_hookpoints(registry)


# ---------------------------------------------------------------------------
# Task 17: supervisor.capability_gate_unavailable is audit-only, not a hookpoint
# ---------------------------------------------------------------------------


def test_supervisor_capability_gate_unavailable_is_audit_event_not_hookpoint() -> None:
    """Spec §8.1: ``supervisor.capability_gate_unavailable`` is an audit event.

    It is emitted via :meth:`AuditWriter.append_schema` directly (see
    :meth:`RealGate._emit_gate_unavailable_audit`), NOT through the hook
    dispatcher. Hooking the audit emit would be circular: when the
    backing store is unavailable, dispatching through the hook chain
    (which can itself fan out to subscribers) would re-enter the same
    failed paths.

    The schema is therefore registered as an
    :data:`SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` constant but
    NOT as a hookpoint in the registry. This test pins the field set
    so a future schema change is loud.
    """
    required = {
        "state_transition",
        "denied_dispatch_count",
        "backing_store_error_type",
        "correlation_id",
    }
    assert required <= SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS


@pytest.mark.parametrize(
    "audit_only_event_name",
    ["supervisor.capability_gate_unavailable"],
)
def test_capability_gate_unavailable_is_not_a_hookpoint(
    audit_only_event_name: str,
) -> None:
    """Importing :mod:`proposals` does NOT register the supervisor event.

    The proposals module declares the four ``plugin.grant.*`` lifecycle
    hookpoints and ONLY those. The supervisor event must not appear in
    the registry — confirming the audit-only contract above. A future
    refactor that accidentally lifts the supervisor event into the
    hookpoint table would surface here.
    """
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    declare_hookpoints(registry)
    assert registry.hookpoint_meta(audit_only_event_name) is None, (
        f"{audit_only_event_name} was promoted to a hookpoint; "
        "spec §8.1 requires it stay an audit-only event."
    )
