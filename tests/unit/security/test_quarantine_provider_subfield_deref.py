"""``QuarantinedExtractor.burst_limiter_policy`` derefs per call (PR-S4-4 Task 18).

The LOW-BLAST per-(user, persona) burst-limiter block is hot-reloadable: a
watcher swap is reflected on the extractor's next deref with no restart. The
HIGH-BLAST ``quarantined_provider_url`` is refused at the watcher layer (see
``tests/unit/policies/test_watcher_behaviour.py::test_high_blast_change_refused``).
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from alfred.security.quarantine import QuarantinedExtractor, declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate
from tests.unit.policies._factories import make_policies, make_snapshot


@pytest.fixture
def fresh_registry() -> Iterator[HookRegistry]:
    """Scoped RealGate registry with the quarantined-extract chain declared."""
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(
            extra_system_plugin_ids=(__name__,),
            extra_operator_plugin_ids=(__name__,),
        ),
        strict_declarations=False,
    )
    try:
        set_registry(registry)
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


def _make_extractor(
    ref: PoliciesSnapshotRef | None, registry: HookRegistry
) -> QuarantinedExtractor:
    dlp = MagicMock()
    dlp.scan = AsyncMock(return_value=None)
    return QuarantinedExtractor(
        transport=MagicMock(),
        audit_writer=MagicMock(),
        outbound_dlp=dlp,
        policies_ref=ref,
    )


def test_burst_limiter_policy_none_without_ref(fresh_registry: HookRegistry) -> None:
    extractor = _make_extractor(None, fresh_registry)
    assert extractor.burst_limiter_policy() is None


def test_burst_limiter_policy_reads_active_snapshot(fresh_registry: HookRegistry) -> None:
    ref = PoliciesSnapshotRef(
        make_snapshot(
            policies=make_policies(
                rate_limits={"quarantined_extract_per_user_persona": {"capacity_tokens": 7}}
            )
        )
    )
    extractor = _make_extractor(ref, fresh_registry)
    policy = extractor.burst_limiter_policy()
    assert policy is not None
    assert policy.capacity_tokens == 7


def test_burst_limiter_policy_reflects_swap_on_next_call(fresh_registry: HookRegistry) -> None:
    ref = PoliciesSnapshotRef(make_snapshot(policies=make_policies()))
    extractor = _make_extractor(ref, fresh_registry)
    assert extractor.burst_limiter_policy().capacity_tokens == 5  # type: ignore[union-attr]
    ref._current = make_snapshot(  # type: ignore[attr-defined]
        policies=make_policies(
            rate_limits={"quarantined_extract_per_user_persona": {"capacity_tokens": 10}}
        )
    )
    assert extractor.burst_limiter_policy().capacity_tokens == 10  # type: ignore[union-attr]
