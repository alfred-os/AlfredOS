"""Verify Slice-4 stub protocols exist and are structurally satisfiable (#174)."""

from __future__ import annotations

from alfred.supervisor.protocols import (
    OperatorResolverProtocol,
    PoliciesSnapshotRefProtocol,
)


def test_policies_snapshot_ref_protocol_is_protocol() -> None:
    assert hasattr(PoliciesSnapshotRefProtocol, "_is_protocol")


def test_operator_resolver_protocol_is_protocol() -> None:
    assert hasattr(OperatorResolverProtocol, "_is_protocol")


def test_minimal_stub_satisfies_snapshot_ref() -> None:
    """A minimal class with the right method shape satisfies the Protocol."""

    class _Stub:
        def current(self) -> object:
            return object()

        def snapshot_hash(self) -> str:
            return "deadbeef"

    stub: PoliciesSnapshotRefProtocol = _Stub()
    assert stub.snapshot_hash() == "deadbeef"


def test_minimal_stub_satisfies_operator_resolver() -> None:
    """A minimal async class satisfies the OperatorResolverProtocol."""

    class _Stub:
        async def resolve(self) -> str:
            return "_daemon_boot"

    stub: OperatorResolverProtocol = _Stub()
    assert stub is not None
