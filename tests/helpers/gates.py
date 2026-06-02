"""Test-only :class:`CapabilityGate` factories — RealGate, no Postgres.

``DevGate`` was removed from ``src/alfred/hooks/capability.py`` at the
end of Slice 3 (PR-S3-7, spec §15.1). This module re-establishes the
ergonomic deny-path / system-grant fixture shapes the old ``DevGate(...)``
constructions used to provide — but ONLY for use in tests, never in
production code. Importing from ``tests.helpers.*`` inside ``src/`` is a
layering violation; the public-surface invariant test pins that the
``alfred.hooks`` package exports no ``DevGate`` symbol.

The production gate is :class:`alfred.security.capability_gate._gate.RealGate`,
constructed by :mod:`alfred.bootstrap.gate_factory` based on the
``ALFRED_ENV`` env var. Tests that need the deny-path semantics of the
old ``DevGate`` use :func:`make_deny_all_gate` here, which wraps
:class:`RealGate` with an in-memory stub backend (no testcontainer, no
Postgres) seeded with an empty grant set — every check call denies by
fail-closed default (spec §8.1 / CLAUDE.md hard rule #7).

Tests that need the granted-system semantics use
:func:`make_allow_system_gate`, which seeds a single ``system``-tier
grant covering the requested ``(plugin_id, hookpoint)`` pair so the
production gate code path returns ``True`` for that exact triple
(equivalent to the old ``DevGate(allow_system=True).check(...)`` answer
in a deny-by-default world).

Usage::

    from tests.helpers.gates import make_allow_system_gate, make_deny_all_gate

    gate = make_deny_all_gate()           # all checks deny
    gate = make_allow_system_gate()       # one wildcard system-tier grant
    gate = make_allow_system_gate(        # narrowed grant
        plugin_id="alfred.web-fetch",
        hookpoint="tool.web.fetch",
    )

The factories return the production :class:`RealGate` type so isinstance
checks against :class:`alfred.hooks.capability.CapabilityGate` continue
to pass — the test shim does NOT introduce a parallel gate hierarchy.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.hooks.capability import CapabilityGate
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow


def _make_in_memory_backend(grants: Iterable[GrantRow] = ()) -> Any:
    """Return a :class:`StorageBackend`-shaped stub pre-loaded with ``grants``.

    The stub satisfies the structural :class:`StorageBackend` Protocol
    without any database I/O: every async method is an :class:`AsyncMock`.
    Tests that drive the test-shim gate consult the in-memory
    :class:`GatePolicy` snapshot, not the backend, so the backend's
    return values only matter on the heartbeat path — which tests can
    opt out of by leaving ``start_heartbeat=False``.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset(grants))
    backend.get_sync_hash = AsyncMock(return_value=None)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    return backend


def _make_no_op_audit_sink() -> Any:
    """Return an audit-sink stub for tests that don't assert on rows.

    err-003: :meth:`RealGate.create` requires an audit sink so a
    fail-closed state transition cannot land without an audit row. The
    test shim is only used in deny-path / granted-path fixtures where
    audit emission isn't the property under test — the no-op sink
    satisfies the constructor contract without inflating the test
    surface area.
    """
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def make_deny_all_gate() -> CapabilityGate:
    """Return a :class:`RealGate` with an empty grant store.

    Equivalent to the old ``DevGate()`` (no args) for deny-path tests:
    no grants ⇒ every :meth:`RealGate.check` /
    :meth:`RealGate.check_plugin_load` /
    :meth:`RealGate.check_content_clearance` call returns ``False``
    (spec §8.1 fail-closed default).

    Synchronous construction (no ``await``) so this can be called from
    pytest fixtures without ``@pytest.mark.asyncio`` overhead — bypasses
    the :meth:`RealGate.create` async factory and goes through
    :meth:`RealGate.__init__` directly with a pre-built empty
    :class:`GatePolicy`. The heartbeat task is NOT started, so callers
    don't need to manage cancellation in a fixture teardown.
    """
    return RealGate(
        policy=GatePolicy(grants=frozenset()),
        backend=_make_in_memory_backend(),
        audit_sink=_make_no_op_audit_sink(),
    )


def make_allow_system_gate(
    *,
    plugin_id: str = "test-plugin",
    hookpoint: str = "*",
) -> CapabilityGate:
    """Return a :class:`RealGate` with one ``system``-tier grant seeded.

    Equivalent to the old ``DevGate(allow_system=True)`` for granted-
    system tests, but the new shape consults the grant table — a
    ``system`` request that doesn't match ``(plugin_id, hookpoint,
    "system")`` still denies. Tests that need the broad "every system
    request grants" posture should pass the default ``hookpoint="*"``
    (wildcard) so any hookpoint matches under that plugin_id.

    The default ``plugin_id="test-plugin"`` matches the convention used
    by the pre-removal ``HookRegistry(gate=DevGate(allow_system=True))``
    fixtures, where ``plugin_id`` was unused — every registration
    succeeded because ``DevGate`` ignored the parameter. Tests that
    rely on a specific plugin id should pass it explicitly.

    The seeded grant carries:

    * ``subscriber_tier="system"`` — the axis under test.
    * ``content_tier=None`` — no content-tier restriction (the
      orthogonal trust axis isn't asserted by the system-tier path).
    * ``proposal_branch="test-fixture"`` — an obviously-test value so
      audit-graph queries don't surface this as a real proposal.
    """
    grant = GrantRow(
        plugin_id=plugin_id,
        subscriber_tier="system",
        hookpoint=hookpoint,
        content_tier=None,
        proposal_branch="test-fixture",
    )
    return RealGate(
        policy=GatePolicy(grants=frozenset({grant})),
        backend=_make_in_memory_backend(grants={grant}),
        audit_sink=_make_no_op_audit_sink(),
    )


__all__ = ["make_allow_system_gate", "make_deny_all_gate"]
