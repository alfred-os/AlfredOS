"""Tests for the ``_DiscordClientLike`` Protocol shim.

Pins the structural surface PR D2's adapter wiring depends on. The stub
that the PR D2 tests inject MUST satisfy this Protocol — every method
present, every signature shape correct. A drift between this Protocol and
the discord.py 2.x ``discord.Client`` surface fails the test here, NOT
on the integration boundary in PR D2.
"""

from __future__ import annotations

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
