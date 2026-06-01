"""Adversarial tier_laundering — in-flight grant revocation race.

Spec §8.1: ``RealGate._apply_grants`` MUST swap the in-memory
:class:`GatePolicy` snapshot atomically — any hot-path ``check`` call
mid-flight sees either the old or the new policy, never a half-mutated
state. The single-threaded asyncio event loop guarantees the atomicity
of the policy-object reassignment; the revoke-then-upsert-then-swap
ordering in ``_apply_grants`` guarantees that any check completing
under the OLD policy completes BEFORE the new policy is observable.

This module covers the in-flight race threat model from the operator
side: a long-running dispatch overlaps with an operator revoking the
underlying grant. Without atomic swap, the operator could revoke the
grant in state.git, observe the audit row, and still have one more
dispatch land under the old policy — a tier-laundering shape that
breaks the audit-graph contract.

The defence under test is structural — the gate's in-memory policy is
a frozen :class:`GatePolicy` and the swap is single-statement
assignment on the asyncio thread. The pytest below exercises the
attack shape: dispatch a ``check`` under the original policy, apply
the revocation, then assert that the second ``check`` denies AND the
backend's ``revoke_grant`` was called for the disappeared grant.

Spec §8.1, §8.5, §12.2. Payload id: ``tl-2026-007``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final
from unittest.mock import AsyncMock, MagicMock

import yaml

from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GrantRow

_PAYLOAD_ID: Final[str] = "tl-2026-007"
_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "tl_inflight_grant_revocation_race.yaml"


def _make_backend() -> Any:
    """Return a stub StorageBackend matching the unit-tier shape.

    Mirrors ``tests/unit/security/capability_gate/test_real_gate.py::
    _make_backend`` so this adversarial test exercises the same wiring
    as the runtime invariant — the corpus contract is "the gate's
    in-memory policy is atomically swapped against the production
    StorageBackend Protocol", not against a bespoke fake.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset())
    backend.get_sync_hash = AsyncMock(return_value=None)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    return backend


def _make_no_op_sink() -> Any:
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def test_payload_yaml_present_and_well_formed() -> None:
    """Drift-guard: the ``tl-2026-007`` YAML exists with expected shape."""
    assert _PAYLOAD_PATH.exists(), f"Missing adversarial payload {_PAYLOAD_PATH.name}"
    payload = yaml.safe_load(_PAYLOAD_PATH.read_text())
    assert payload["id"] == _PAYLOAD_ID
    assert payload["category"] == "tier_laundering"
    assert payload["ingestion_path"] == "capability_gate"
    assert payload["expected_outcome"] == "audit_row_emitted"


async def test_inflight_check_under_revoked_grant_denies_after_apply() -> None:
    """A ``check`` after ``_apply_grants(empty_set)`` denies; revoke_grant fires.

    Sequence simulates the in-flight race:

    1. Initial grant admits ``check(plugin_id, hookpoint,
       requested_tier)`` — the in-flight dispatch's first consult.
    2. Operator revokes the grant; ``_apply_grants(frozenset())`` swaps
       the policy to the empty snapshot.
    3. The second ``check`` (e.g. a hypothetical re-check before the
       dispatch returns) MUST deny — there is no intermediate state
       in which the old policy answers under the new audit attribution.

    Asserts the operator-side audit-graph property: the backend's
    ``revoke_grant`` is called exactly once per disappeared grant, and
    the post-swap ``check`` returns ``False``. The pre-swap ``check``
    returns ``True`` from the same gate instance under the OLD policy
    — proving the swap is the boundary, not a partial mutation.
    """
    grant = GrantRow(
        plugin_id="alfred.compromised-plugin",
        subscriber_tier="user-plugin",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-original",
    )

    backend = _make_backend()
    backend.load_grants = AsyncMock(return_value=frozenset({grant}))
    gate = await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())

    # 1. In-flight dispatch: under the original policy the check admits.
    assert (
        gate.check(
            plugin_id="alfred.compromised-plugin",
            hookpoint="tool.web.fetch",
            requested_tier="user-plugin",
        )
        is True
    )

    # 2. Operator revokes the grant; reviewer merges; the host invokes
    #    _apply_grants with the new (empty) snapshot.
    await gate._apply_grants(frozenset(), commit_hash="commit-after-revoke")

    # The disappeared grant triggers a backend.revoke_grant call —
    # this is the Postgres-projection side of the audit graph (every
    # in-memory revoke MUST land in the persistence layer too;
    # CR-139 finding #2 codified this).
    backend.revoke_grant.assert_awaited_once_with(
        plugin_id="alfred.compromised-plugin",
        hookpoint="tool.web.fetch",
        subscriber_tier="user-plugin",
    )
    # The post-swap sync hash MUST also land — the audit-graph
    # forensic-traversal layer keys off it.
    backend.set_sync_hash.assert_awaited_once_with("commit-after-revoke")

    # 3. The post-swap check denies. The race shape — "in-flight call
    #    completes under old policy AFTER the swap is observable" — is
    #    impossible: the in-memory snapshot has been replaced.
    assert (
        gate.check(
            plugin_id="alfred.compromised-plugin",
            hookpoint="tool.web.fetch",
            requested_tier="user-plugin",
        )
        is False
    )


async def test_revoke_then_upsert_ordering_preserves_audit_graph() -> None:
    """``_apply_grants`` calls revoke BEFORE upsert; sync_hash lands LAST.

    Pins the spec §8.1 ordering. The audit graph traversal relies on
    "every disappeared grant produced one revoke_grant before any new
    grant produced its upsert" — without that, a content-tier-widening
    change could land its new upsert BEFORE the old grant's revoke
    audit row, producing a brief window where Postgres reports the
    expanded grant while the state.git proposal_branch still cites the
    original.
    """
    original_grant = GrantRow(
        plugin_id="alfred.web-fetch",
        subscriber_tier="user-plugin",
        hookpoint="tool.web.fetch",
        content_tier="T2",
        proposal_branch="proposal/policy-grant-original",
    )

    backend = _make_backend()
    backend.load_grants = AsyncMock(return_value=frozenset({original_grant}))
    gate = await RealGate.create(backend=backend, audit_sink=_make_no_op_sink())

    # New snapshot: the original grant is gone (revoked) AND a fresh
    # grant takes its place on a different hookpoint.
    new_grant = GrantRow(
        plugin_id="alfred.web-fetch",
        subscriber_tier="user-plugin",
        hookpoint="tool.email.read",
        content_tier="T2",
        proposal_branch="proposal/policy-grant-replacement",
    )
    await gate._apply_grants(frozenset({new_grant}), commit_hash="commit-after-swap")

    # Revoke fires exactly once for the disappeared grant.
    backend.revoke_grant.assert_awaited_once_with(
        plugin_id="alfred.web-fetch",
        hookpoint="tool.web.fetch",
        subscriber_tier="user-plugin",
    )
    # Upsert fires exactly once for the new grant.
    backend.upsert_grant.assert_awaited_once_with(new_grant)
    # The sync hash lands AFTER both — the audit-graph terminal anchor.
    backend.set_sync_hash.assert_awaited_once_with("commit-after-swap")

    # And the gate now answers per the new policy: the old hookpoint
    # denies, the new one admits.
    assert (
        gate.check(
            plugin_id="alfred.web-fetch",
            hookpoint="tool.web.fetch",
            requested_tier="user-plugin",
        )
        is False
    )
    assert (
        gate.check(
            plugin_id="alfred.web-fetch",
            hookpoint="tool.email.read",
            requested_tier="user-plugin",
        )
        is True
    )
