"""Tests for the ``CommsAdapter`` Protocol + ``AdapterHealth`` dataclass.

Pins the cross-PR contract surface published by PR D1 (CommsAdapter +
AdapterHealth). PR D2's Discord adapter and Slice-3's MCP-transport
rewrite both consume this shape — changing it without a coordinated
multi-PR refactor is a breaking change. The structural-typing tests below
are deliberately strict so a silent signature drift fails CI.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from alfred.comms.adapter import AdapterHealth, CommsAdapter


class _GoodStub:
    """Stub adapter satisfying every method on :class:`CommsAdapter`."""

    name: str = "stub"

    async def start(self) -> None:
        return None

    async def run(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def health(self) -> AdapterHealth:
        return AdapterHealth(
            gateway_connected=True,
            last_on_ready_at=datetime.now(UTC),
            recent_reconnect_count=0,
        )


class _MissingMethodStub:
    """Stub that lacks ``health``; must NOT satisfy the Protocol."""

    name: str = "broken"

    async def start(self) -> None:
        return None

    async def run(self) -> None:
        return None

    async def stop(self) -> None:
        return None


def test_good_stub_satisfies_protocol() -> None:
    assert isinstance(_GoodStub(), CommsAdapter)


def test_missing_method_stub_fails_protocol_check() -> None:
    assert not isinstance(_MissingMethodStub(), CommsAdapter)


def test_adapter_health_is_frozen_dataclass() -> None:
    health = AdapterHealth(
        gateway_connected=True,
        last_on_ready_at=None,
        recent_reconnect_count=0,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        # Intentional mutation attempt — verifies frozenness contract.
        health.gateway_connected = False  # type: ignore[misc]


def test_adapter_health_carries_three_documented_fields() -> None:
    fields = {f.name for f in dataclasses.fields(AdapterHealth)}
    assert fields == {"gateway_connected", "last_on_ready_at", "recent_reconnect_count"}


def test_adapter_health_accepts_none_timestamp() -> None:
    # Sentinel-value test: a TUI that has never reached ``start()`` reports
    # ``last_on_ready_at=None`` per the docstring.
    health = AdapterHealth(
        gateway_connected=False,
        last_on_ready_at=None,
        recent_reconnect_count=0,
    )
    assert health.last_on_ready_at is None
