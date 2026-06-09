"""Test fixtures for the PR-S4-4 policy snapshot ref (rev-003 closure).

``Supervisor.__init__`` takes ``policies_ref`` as a REQUIRED kwarg — production
refuses to run the privileged orchestrator with no policy snapshot. For test
isolation, :class:`_StubPoliciesSnapshotRef` provides a minimal ref satisfying
``PoliciesSnapshotRefProtocol`` (``current`` + ``snapshot_hash``).
"""

from __future__ import annotations

import pytest

from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
from tests.unit.policies._factories import make_snapshot


class _StubPoliciesSnapshotRef:
    """Minimal ``PoliciesSnapshotRefProtocol`` stub for supervisor unit tests."""

    def __init__(self, snapshot: PoliciesSnapshot | None = None) -> None:
        self._snapshot = snapshot if snapshot is not None else make_snapshot()

    def current(self) -> PoliciesSnapshot:
        return self._snapshot

    def snapshot_hash(self) -> str:
        return self._snapshot.file_sha256


@pytest.fixture
def stub_policies_ref() -> _StubPoliciesSnapshotRef:
    """A ready-to-pass ``policies_ref`` for ``Supervisor(...)`` constructions."""
    return _StubPoliciesSnapshotRef()


def real_policies_ref() -> PoliciesSnapshotRef:
    """A concrete :class:`PoliciesSnapshotRef` seeded with a valid snapshot."""
    return PoliciesSnapshotRef(make_snapshot())


__all__ = ["_StubPoliciesSnapshotRef", "real_policies_ref", "stub_policies_ref"]
