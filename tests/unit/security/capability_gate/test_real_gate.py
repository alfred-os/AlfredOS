"""Unit tests for :class:`alfred.security.capability_gate.RealGate`.

Spec §8.1 / §8.2 (PR-S3-2). The production
:class:`alfred.hooks.capability.CapabilityGate` implementation. The
backing store is stubbed via a :class:`StorageBackend` MagicMock so the
suite stays driver-free; the heartbeat / fail-closed machinery and the
state.git rebuild are covered in Components E-F and PR-S3-6 respectively.

Hard invariants pinned here (PR-S3-2 Tasks 7-8 batch):

* **Happy path** — a present grant grants on ``check`` / ``check_plugin_load``
  / ``check_content_clearance``; an absent grant denies.
* **Policy dispatch** — :class:`RealGate` delegates each method to
  :class:`GatePolicy`. The gate is a thin wrapper above the pure policy;
  any logic creep into the gate body would surface here.
* **Protocol membership** — :class:`RealGate` satisfies
  :class:`CapabilityGate` structurally. The dispatcher's ``isinstance``
  narrow holds without a registry.
* **Required audit_sink** — :meth:`RealGate.create` requires an
  ``audit_sink`` parameter. ``None`` is a misconfiguration — err-003
  fix per spec §8.1 / CLAUDE.md hard rule #7 (a fail-closed state
  transition without an audit row is a silent security event).
* **rebuild_from_state_git is a fail-loud deferred stub** — err-002
  acknowledgement. Calling it raises :class:`NotImplementedError`
  citing PR-S3-6 as the wiring PR. Direct callers use ``_apply_grants``
  until then.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.security.capability_gate.policy import GrantRow


def _make_backend(
    grants: frozenset[GrantRow] | None = None,
    sync_hash: str | None = None,
) -> Any:
    """Return a stub StorageBackend with pre-loaded grants."""
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=grants or frozenset())
    backend.get_sync_hash = AsyncMock(return_value=sync_hash)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    return backend


def _make_no_op_sink() -> Any:
    """Return a no-op audit sink for tests that don't assert audit rows.

    err-003 fix: audit_sink is REQUIRED on :meth:`RealGate.create`. Tests
    that only check gate behaviour (not audit emission) use this sink so
    they don't need to assert on ``append_schema`` calls. The sink uses
    ``append_schema(fields, **kwargs)`` per Cluster 4 / rvw-001.
    """
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


async def test_real_gate_check_returns_true_for_existing_grant() -> None:
    """Happy path: a present grant grants on :meth:`RealGate.check`."""
    from alfred.security.capability_gate._gate import RealGate

    grant = GrantRow(
        plugin_id="test.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-abc",
    )
    gate = await RealGate.create(
        backend=_make_backend(grants=frozenset({grant})),
        audit_sink=_make_no_op_sink(),
    )
    assert (
        gate.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )


async def test_real_gate_check_returns_false_for_no_grant() -> None:
    """Fail-closed: an empty policy denies every :meth:`check`."""
    from alfred.security.capability_gate._gate import RealGate

    gate = await RealGate.create(
        backend=_make_backend(grants=frozenset()),
        audit_sink=_make_no_op_sink(),
    )
    assert (
        gate.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )


async def test_real_gate_check_plugin_load_delegates_to_policy() -> None:
    """``check_plugin_load`` delegates to the GatePolicy method of the same name.

    A wildcard-hookpoint grant covers any subsequent plugin-load check
    at the matching subscriber_tier. A mismatch in tier denies even when
    the plugin_id matches — spec §8.2 (orthogonal axes).
    """
    from alfred.security.capability_gate._gate import RealGate

    grant = GrantRow(
        plugin_id="mypl",
        subscriber_tier="system",
        hookpoint="*",
        content_tier=None,
        proposal_branch="proposal/policy-grant-xyz",
    )
    gate = await RealGate.create(
        backend=_make_backend(grants=frozenset({grant})),
        audit_sink=_make_no_op_sink(),
    )
    assert gate.check_plugin_load(plugin_id="mypl", manifest_tier="system") is True
    assert gate.check_plugin_load(plugin_id="mypl", manifest_tier="operator") is False


async def test_real_gate_check_content_clearance_delegates_to_policy() -> None:
    """``check_content_clearance`` delegates to GatePolicy.check_content_clearance.

    Spec §8.2: the orthogonal content-tier axis. Only the plugin holding
    the matching content_tier grant is cleared.
    """
    from alfred.security.capability_gate._gate import RealGate

    grant = GrantRow(
        plugin_id="quarantine.host",
        subscriber_tier="system",
        hookpoint="tag.T3",
        content_tier="T3",
        proposal_branch="proposal/policy-grant-t3",
    )
    gate = await RealGate.create(
        backend=_make_backend(grants=frozenset({grant})),
        audit_sink=_make_no_op_sink(),
    )
    assert (
        gate.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is True
    )
    assert (
        gate.check_content_clearance(
            plugin_id="other",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is False
    )


async def test_real_gate_satisfies_capability_gate_protocol() -> None:
    """:class:`RealGate` is structurally a :class:`CapabilityGate`."""
    from alfred.hooks.capability import CapabilityGate
    from alfred.security.capability_gate._gate import RealGate

    gate = await RealGate.create(
        backend=_make_backend(),
        audit_sink=_make_no_op_sink(),
    )
    assert isinstance(gate, CapabilityGate)


async def test_real_gate_create_loads_grants_from_backend() -> None:
    """:meth:`RealGate.create` calls ``backend.load_grants`` exactly once.

    The initial load is from Postgres (millisecond latency). The state.git
    rebuild happens separately via ``rebuild_from_state_git`` (deferred to
    PR-S3-6).
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(grants=frozenset())
    await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())
    backend.load_grants.assert_awaited_once()


async def test_real_gate_create_does_not_start_heartbeat_by_default() -> None:
    """Default-constructed RealGate does NOT start the heartbeat task.

    Tests need to inspect / advance state without a background task
    racing them. ``start_heartbeat=True`` opts in explicitly; the
    heartbeat behaviour itself is covered by Component E tests in a
    later PR-S3-2 task.
    """
    from alfred.security.capability_gate._gate import RealGate

    gate = await RealGate.create(
        backend=_make_backend(),
        audit_sink=_make_no_op_sink(),
    )
    # No heartbeat task running.
    assert gate._heartbeat_task is None  # type: ignore[attr-defined]


async def test_real_gate_rebuild_from_state_git_is_fail_loud_stub() -> None:
    """``rebuild_from_state_git`` raises ``NotImplementedError`` when the head differs.

    err-002 fix: the previous silent ``return`` left the policy cache
    stale without surfacing the contract violation. PR-S3-6 wires the
    real gitpython-backed parser; until then, the gate raises so
    callers fail loudly at integration time rather than silently caching
    nothing.

    The match string MUST cite the deferred-stub contract so a future
    grep surfaces every site relying on the stub.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(sync_hash="old-hash")
    gate = await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())
    with pytest.raises(NotImplementedError, match="gitpython state.git parser"):
        await gate.rebuild_from_state_git(state_git_head="new-hash")


async def test_real_gate_rebuild_from_state_git_short_circuits_when_unchanged() -> None:
    """``rebuild_from_state_git`` no-ops when the head matches the cached hash.

    Spec §8.1: the rebuild check is idempotent. When the cached commit
    matches the requested head, the gate skips the rebuild without
    raising — distinct from the err-002 deferred-stub branch (head differs).
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(sync_hash="abc123")
    gate = await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())
    # No exception, no rebuild.
    await gate.rebuild_from_state_git(state_git_head="abc123")
    backend.set_sync_hash.assert_not_called()


async def test_real_gate_apply_grants_swaps_policy_and_persists() -> None:
    """``_apply_grants`` updates the in-memory policy AND persists to backend.

    Spec §8.1: the host (PR-S3-6 caller) provides already-parsed
    GrantRows. This method is the public entry point until
    rebuild_from_state_git is fully wired in PR-S3-6. The grants must
    land in both the policy snapshot (for next hot-path check) and
    Postgres (for the next process to load on startup).
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(grants=frozenset())
    gate = await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())

    new_grant = GrantRow(
        plugin_id="newpl",
        subscriber_tier="operator",
        hookpoint="*",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new",
    )
    await gate._apply_grants(
        frozenset({new_grant}),
        commit_hash="new-head-hash",
    )

    # Backend received the upsert and sync-hash set.
    backend.upsert_grant.assert_awaited_once_with(new_grant)
    backend.set_sync_hash.assert_awaited_once_with("new-head-hash")

    # In-memory policy now answers the new grant positively.
    assert (
        gate.check(
            plugin_id="newpl",
            hookpoint="anything",
            requested_tier="operator",
        )
        is True
    )
