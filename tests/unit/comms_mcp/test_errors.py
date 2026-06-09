"""``alfred.comms_mcp.errors`` hierarchy (PR-S4-8)."""

from __future__ import annotations

import pytest

from alfred.comms_mcp.errors import (
    CommsHandlerFailedError,
    CommsMcpError,
    InboundBurstDroppedError,
    UnknownAdapterKindError,
)
from alfred.errors import AlfredError


def test_root_inherits_alfred_error() -> None:
    assert issubclass(CommsMcpError, AlfredError)


def test_subclasses_inherit_root() -> None:
    for cls in (
        UnknownAdapterKindError,
        InboundBurstDroppedError,
        CommsHandlerFailedError,
    ):
        assert issubclass(cls, CommsMcpError)


def test_instances_are_raisable() -> None:
    with pytest.raises(CommsMcpError):
        raise UnknownAdapterKindError("evil")
