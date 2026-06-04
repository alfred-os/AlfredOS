"""Hookpoint metadata pin for ``security.quarantined.extract`` (issue #158).

Spec §6.5 + §14: the privileged orchestrator's quarantined-extraction
chain MUST be declared with ``SYSTEM_OPERATOR_TIERS`` subscribers,
``SYSTEM_ONLY_TIERS`` refusers, and ``fail_closed=True``. Weakening any
of the three on the publisher side silently disarms the trust boundary
the spec mandates — pin every field directly here so a typo at the
declaration site fails this test rather than landing as an audit-log
silent regression.

The hookpoint declaration runs at ``alfred.security.quarantine``
module-init time (see :func:`alfred.security.quarantine.declare_hookpoints`
— matches the precedent at :mod:`alfred.memory.episodic`). The test
imports the module solely for that side effect, then reads the
:class:`HookpointMeta` back out of the global registry's private
``_hookpoints`` map and asserts the contract.
"""

from __future__ import annotations

from alfred.hooks import (
    SYSTEM_ONLY_TIERS,
    SYSTEM_OPERATOR_TIERS,
    get_registry,
)


def test_hookpoint_registered_at_module_import() -> None:
    """Importing :mod:`alfred.security.quarantine` MUST register the
    ``security.quarantined.extract`` hookpoint with the exact spec §6.5
    metadata.

    Three field-level asserts because spec §6.5 spells out each one
    distinctly — a single ``meta == HookpointMeta(...)`` comparison
    would lump the failure modes into one error message, making
    diagnosis harder when only one field drifts (e.g. a future author
    relaxes ``fail_closed`` to ``False`` without noticing).
    """
    import alfred.security.quarantine  # noqa: F401 — import for side effect

    meta = get_registry().hookpoint_meta("security.quarantined.extract")
    assert meta is not None, (
        "security.quarantined.extract MUST be declared at module-init time "
        "via alfred.security.quarantine.declare_hookpoints()."
    )
    assert meta.subscribable_tiers == SYSTEM_OPERATOR_TIERS, (
        "subscribable_tiers MUST be SYSTEM_OPERATOR_TIERS (spec §6.5) — "
        "user-plugin subscribers MUST NOT register against the "
        "quarantined-extract post chain."
    )
    assert meta.refusable_tiers == SYSTEM_ONLY_TIERS, (
        "refusable_tiers MUST be SYSTEM_ONLY_TIERS (spec §6.5) — only "
        "system-tier subscribers may refuse an extract."
    )
    assert meta.fail_closed is True, (
        "fail_closed MUST be True (spec §6.5) — a subscriber crash or "
        "timeout on the trust boundary MUST raise, not silently pass."
    )


def test_declare_hookpoints_is_idempotent() -> None:
    """Calling :func:`alfred.security.quarantine.declare_hookpoints` a
    second time on the same registry MUST NOT raise.

    The registry's contract (see
    :meth:`alfred.hooks.registry.HookRegistry.register_hookpoint`) is
    that an identical re-declaration is a no-op — important because
    :mod:`pytest`'s test-isolation fixtures may swap the registry and
    cause the module-bottom call to re-run. A non-idempotent
    declaration would raise :class:`HookError` and break every test
    that subsequently imports the module.
    """
    from alfred.security.quarantine import declare_hookpoints

    # Re-import-time call has already happened. A bare re-call against
    # the current registry MUST succeed.
    declare_hookpoints()


def test_user_tier_subscription_refused() -> None:
    """Pin HIGH #4 (CR-158): a ``user-plugin`` subscriber attempting
    to register against ``security.quarantined.extract`` MUST be
    refused at register-time AND a :data:`HOOKS_TIER_REJECTED` audit
    row MUST land BEFORE the :class:`HookError` raise.

    The hookpoint's ``subscribable_tiers`` is
    :data:`SYSTEM_OPERATOR_TIERS` (spec §6.5) — user-plugin is
    deliberately locked out so an untrusted third-party plugin
    cannot wedge into the trust boundary. The registry's #119
    register-time check is what enforces this; the audit row is the
    forensic record an operator grep'd against.

    The test uses a scoped grant gate
    (``make_quarantined_extract_chain_gate``) so the gate setup
    mirrors production checks; the gate itself is NOT the refuser.
    The expected failure path here is the publisher tier-allowlist
    check, not capability-gate denial.
    """
    from collections.abc import Mapping
    from dataclasses import dataclass, field

    import pytest as _pytest

    from alfred.hooks import HookError, HookRegistry, set_registry
    from alfred.hooks.audit_sink import HOOKS_TIER_REJECTED
    from alfred.security.quarantine import declare_hookpoints
    from tests.helpers.gates import make_quarantined_extract_chain_gate

    @dataclass(frozen=True, slots=True)
    class _SpyAuditSink:
        calls: list[dict[str, object]] = field(default_factory=list)

        async def emit(
            self,
            *,
            event: str,
            correlation_id: str,
            fields: Mapping[str, object],
        ) -> None:
            self.calls.append(
                {
                    "event": event,
                    "correlation_id": correlation_id,
                    "fields": dict(fields),
                }
            )

    sink = _SpyAuditSink()
    # CR-156 round-7 / CR-158 T4 (CLAUDE.md hard rule #2): scoped
    # :class:`RealGate` — NOT
    # ``make_permissive_fixture_gate(allow_system=True)``. The shim
    # ignores ``plugin_id`` / ``hookpoint`` so a regression in the
    # registry's grant-policy check would be invisible. The scoped
    # gate seeds a system-tier grant for the quarantined-extract
    # chain; the gate-check would deny user-plugin anyway, but the
    # publisher's ``subscribable_tiers`` allow-list refusal fires
    # FIRST (registry.py register-order: strict-declarations →
    # tier-allowlist → gate). The :data:`HOOKS_TIER_REJECTED` row
    # asserted below is the publisher's load-bearing audit signal.
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        sink=sink,
        strict_declarations=True,
    )
    prior = get_registry()
    set_registry(registry)
    try:
        declare_hookpoints(registry)

        async def _user_plugin_attempt(_ctx: object) -> None:
            return None

        # ignore: we deliberately use the production HookRegistry surface
        # to assert a register-time refusal; no test-shim shortcuts.
        with _pytest.raises(HookError):
            registry.register(
                hook_fn=_user_plugin_attempt,
                hookpoint="security.quarantined.extract",
                kind="post",
                tier="user-plugin",
            )

        # Subscriber bucket stays empty — the refused registration
        # MUST leave no trace (fail-closed).
        subs = registry.subscribers_for("security.quarantined.extract", "post")
        assert subs == ()

        # And the HOOKS_TIER_REJECTED audit row landed BEFORE the
        # raise (the registry calls ``_emit_sync`` before raising
        # :class:`HookError`).
        tier_rows = [c for c in sink.calls if c["event"] == HOOKS_TIER_REJECTED]
        assert len(tier_rows) == 1, (
            f"Expected exactly one HOOKS_TIER_REJECTED row; got "
            f"{[c['event'] for c in sink.calls]!r}"
        )
        row_fields = tier_rows[0]["fields"]
        assert isinstance(row_fields, dict)
        assert row_fields["hookpoint"] == "security.quarantined.extract"
        assert row_fields["subscriber_tier"] == "user-plugin"
        assert "system" in row_fields["subscribable_tiers"]
        assert "operator" in row_fields["subscribable_tiers"]
        assert "user-plugin" not in row_fields["subscribable_tiers"]
    finally:
        set_registry(prior)
