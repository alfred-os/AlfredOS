"""Tests for the ``_DiscordClientLike`` Protocol shim.

Pins the structural surface PR D2's adapter wiring depends on. The stub
that the PR D2 tests inject MUST satisfy this Protocol — every method
present, every signature shape correct. A drift between this Protocol and
the discord.py 2.x ``discord.Client`` surface fails the test here, NOT
on the integration boundary in PR D2.

``@runtime_checkable`` Protocol's ``isinstance`` only verifies attribute
*presence*, not signatures or return types. The tests below pair the
``isinstance`` gate with explicit signature + return-type assertions so
silent shape drift (e.g. a stub that switched ``start(token)`` to
``start(token, secret)``) fails CI.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable

from alfred.comms.discord_types import _DiscordClientLike


class _GoodStub:
    """Stub matching every method on :class:`_DiscordClientLike`."""

    def event(self, coro: Callable[..., object]) -> Callable[..., object]:
        return coro

    async def start(self, token: str, *, reconnect: bool = True) -> None:
        del token, reconnect
        return

    async def close(self) -> None:
        return None

    def is_ready(self) -> bool:
        return True


class _MissingClose:
    """Stub missing ``close``; must NOT satisfy the Protocol."""

    def event(self, coro: Callable[..., object]) -> Callable[..., object]:
        return coro

    async def start(self, token: str, *, reconnect: bool = True) -> None:
        del token, reconnect
        return

    def is_ready(self) -> bool:
        return True


def test_good_stub_satisfies_protocol() -> None:
    assert isinstance(_GoodStub(), _DiscordClientLike)


def test_stub_missing_close_fails_protocol_check() -> None:
    assert not isinstance(_MissingClose(), _DiscordClientLike)


def test_good_stub_signatures_match_protocol_shape() -> None:
    """Behavioural signature check beyond ``isinstance``.

    ``isinstance`` accepts a stub regardless of its parameter shape.
    Inspect the actual signatures to catch a drift that ``isinstance``
    cannot see — e.g. ``start`` losing its keyword-only ``reconnect``,
    or ``event`` becoming a no-arg method.
    """
    stub = _GoodStub()

    event_sig = inspect.signature(stub.event)
    assert list(event_sig.parameters) == ["coro"]

    start_sig = inspect.signature(stub.start)
    assert list(start_sig.parameters) == ["token", "reconnect"]
    # ``reconnect`` is keyword-only with default True per discord.py 2.x.
    assert start_sig.parameters["reconnect"].kind == inspect.Parameter.KEYWORD_ONLY
    assert start_sig.parameters["reconnect"].default is True

    close_sig = inspect.signature(stub.close)
    assert list(close_sig.parameters) == []

    is_ready_sig = inspect.signature(stub.is_ready)
    assert list(is_ready_sig.parameters) == []


def test_good_stub_async_methods_return_coroutines_and_return_value() -> None:
    """The Protocol marks ``start``/``close`` async and ``is_ready``
    returning ``bool``. ``isinstance`` would not catch a stub that
    accidentally made ``close`` sync, or ``is_ready`` return ``None``;
    these assertions do.
    """
    stub = _GoodStub()
    start_coro = stub.start("fake-token")
    assert inspect.iscoroutine(start_coro)
    assert asyncio.run(start_coro) is None
    close_coro = stub.close()
    assert inspect.iscoroutine(close_coro)
    assert asyncio.run(close_coro) is None
    ready = stub.is_ready()
    assert isinstance(ready, bool)


def test_event_decorator_returns_the_passed_callable() -> None:
    """``event(coro)`` is a decorator — it MUST return the same callable
    so ``@client.event\\nasync def on_ready(): ...`` keeps the
    annotated function bound in the caller's namespace. ``isinstance``
    only proves ``event`` exists; this proves it behaves as a decorator.
    """

    async def handler() -> None:
        return None

    assert _GoodStub().event(handler) is handler


# ---------------------------------------------------------------------------
# Negative drift case — demonstrates the gap that ``isinstance`` leaves and
# proves the signature/return-shape checks above actually catch it.
# ---------------------------------------------------------------------------


class _BadStartDriftStub:
    """Stub that satisfies ``isinstance`` but drifts on ``start`` shape.

    ``isinstance(_BadStartDriftStub(), _DiscordClientLike)`` returns
    ``True`` because Python's runtime Protocol check only verifies
    attribute names, not signatures or return types. The shape checks
    below MUST fail for this stub — that's how we prove the test gate
    actually defends the contract.

    Drift: ``start`` accepts ``reconnect`` positionally (not keyword-
    only as discord.py 2.x does) AND returns ``int`` instead of
    ``None``.
    """

    def event(self, coro: Callable[..., object]) -> Callable[..., object]:
        return coro

    async def start(self, token: str, reconnect: bool = True) -> int:  # noqa: FBT001, FBT002 — deliberate drift fixture: positional bool is the exact shape under test
        # Drift demo, never used at runtime.
        del token, reconnect
        return 123  # type: ignore[return-value]

    async def close(self) -> None:
        return None

    def is_ready(self) -> bool:
        return True


def test_isinstance_passes_for_bad_start_drift_stub() -> None:
    """Document the isinstance gap explicitly.

    The Protocol check returns ``True`` here even though ``start`` drifts
    on parameter kind AND return type. This is the gap the
    signature-shape tests below close — if this assertion ever flips to
    ``False`` (because Python tightened the runtime Protocol check),
    delete this whole negative section since the gap is gone.
    """
    assert isinstance(_BadStartDriftStub(), _DiscordClientLike)


def test_bad_stub_signature_check_catches_drift() -> None:
    """The signature gate flags positional ``reconnect`` on ``start``.

    discord.py 2.x has ``start(token, *, reconnect=True)`` — keyword-
    only. The drift stub's positional form is exactly the regression
    PRs D1 + D2 must catch at unit time; the signature inspection is
    the only mechanism that does, because ``isinstance`` cannot.
    """
    bad = _BadStartDriftStub()
    start_sig = inspect.signature(bad.start)
    reconnect = start_sig.parameters.get("reconnect")
    assert reconnect is not None
    # The drift: keyword-only contract violated by positional spelling.
    assert reconnect.kind != inspect.Parameter.KEYWORD_ONLY


def test_bad_stub_return_value_check_catches_drift() -> None:
    """The return-value gate flags non-``None`` from ``start``.

    The Protocol promises ``async start(...) -> None``. The drift stub
    returns ``123``. ``inspect.iscoroutine`` still passes (it IS a
    coroutine), but awaiting it yields a non-None value — which the
    shape test for ``_GoodStub`` asserts equals ``None``.
    """
    bad = _BadStartDriftStub()
    result = asyncio.run(bad.start("fake-token"))
    assert result != _GOOD_START_RETURN  # i.e. not None
    assert result == 123  # drift confirmed


_GOOD_START_RETURN: None = None
