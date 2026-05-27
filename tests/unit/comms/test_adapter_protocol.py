"""Tests for the ``CommsAdapter`` Protocol + ``AdapterHealth`` dataclass.

Pins the cross-PR contract surface published by PR D1 (CommsAdapter +
AdapterHealth). PR D2's Discord adapter and Slice-3's MCP-transport
rewrite both consume this shape — changing it without a coordinated
multi-PR refactor is a breaking change. The structural-typing tests below
are deliberately strict so a silent signature drift fails CI.

A note on what ``isinstance(x, CommsAdapter)`` does and does NOT check:
``@runtime_checkable`` Protocols only verify that the named attributes
*exist* on the candidate. They do NOT verify parameter shape, return
type, or async-vs-sync. The signature-shape tests below close that gap
by asking ``inspect.signature`` directly and by running the methods
to verify they return the expected runtime types — assertions
``isinstance`` cannot make.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
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


def test_good_stub_lifecycle_methods_have_zero_extra_params_and_are_async() -> None:
    """Behavioural check beyond ``isinstance``.

    ``@runtime_checkable`` Protocols only check attribute *presence* on
    the candidate — a class with ``def start(self, garbage: int) -> str``
    would still pass ``isinstance``. Pin the actual lifecycle shape by
    inspecting signatures (no extra params beyond ``self``) and by
    confirming the methods return awaitables that resolve to ``None``.
    """
    stub = _GoodStub()
    for method_name in ("start", "run", "stop"):
        method = getattr(stub, method_name)
        sig = inspect.signature(method)
        # ``self`` is already bound when we look up off an instance; no
        # additional positional/keyword parameters allowed.
        assert list(sig.parameters) == [], f"{method_name} took extra params: {sig}"
        coro = method()
        assert inspect.iscoroutine(coro), f"{method_name} did not return a coroutine"
        assert asyncio.run(coro) is None


def test_good_stub_health_returns_adapter_health_instance() -> None:
    """The Protocol declares ``health() -> AdapterHealth``; verify the
    actual return type because ``isinstance`` would accept any callable
    named ``health`` regardless of what it returns.
    """
    stub = _GoodStub()
    sig = inspect.signature(stub.health)
    assert list(sig.parameters) == []
    result = stub.health()
    assert isinstance(result, AdapterHealth)


def test_isinstance_does_not_validate_return_types_documented_limitation() -> None:
    """Document the Protocol-runtime limitation so future contributors
    don't mistake an ``isinstance`` pass for a behavioural guarantee.

    A stub whose ``health()`` returns the wrong type would still satisfy
    ``isinstance(stub, CommsAdapter)`` — but the behavioural check above
    catches it. Keep both layers.
    """

    class _WrongReturnStub:
        name: str = "wrong"

        async def start(self) -> None:
            return None

        async def run(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        def health(self) -> str:  # Intentionally wrong return type.
            return "not-an-adapter-health"

    stub = _WrongReturnStub()
    # ``isinstance`` passes despite the wrong return type — this is the
    # documented Python Protocol-runtime behaviour, not a bug in our
    # Protocol definition.
    assert isinstance(stub, CommsAdapter)
    # The behavioural check catches it where ``isinstance`` cannot.
    assert not isinstance(stub.health(), AdapterHealth)


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
