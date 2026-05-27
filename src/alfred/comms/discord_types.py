"""Structural Protocol shim for the discord.py client surface.

PR D2 ships ``src/alfred/comms/discord.py`` which imports ``discord.py`` and
constructs a real ``discord.Client``. Tests in PR D2 inject a stub client
through a ``client_factory`` callable. That stub must satisfy a structural
type — :class:`_DiscordClientLike` — so the production code path is shared
between the test stub and the real client.

This Protocol lives in ``discord_types.py`` rather than inside
``discord.py`` so PR D2's adapter module (which imports ``discord.py``)
can ``from .discord_types import _DiscordClientLike`` without triggering
the discord.py import in tests that mock the client. The cycle-avoidance
shape was settled in the spec; this module is the load-bearing seam.

The Protocol is underscore-prefixed because it is a test-seam shim, not
part of the public AlfredOS surface. Consumers outside ``alfred.comms``
have no business importing it — the boundary test
``tests/unit/comms/test_no_direct_adapter_imports.py`` only allows
``alfred.comms.discord_types`` from inside the package itself.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable


@runtime_checkable
class _DiscordClientLike(Protocol):
    """Structural surface PR D2's adapter requires from a discord.py client.

    Methods mirror the public discord.py 2.x ``discord.Client`` surface
    we actually call from the adapter:

    * ``event(coro)`` — decorator-shaped registration of an event handler;
      called like ``@client.event\\ndef on_ready(): ...``.
    * ``start(token, *, reconnect=True)`` — async, opens the gateway.
    * ``close()`` — async, tears the gateway down cleanly.
    * ``is_ready()`` — sync, returns the gateway-ready flag.

    Decorating ``event`` as a callable that takes and returns a callable
    keeps the structural check honest: a stub that swaps the decorator
    semantics (e.g. registers eagerly without returning the function)
    silently breaks adapter wiring and the test would catch it.
    """

    def event(self, coro: Callable[..., object]) -> Callable[..., object]:
        raise NotImplementedError

    async def start(self, token: str, *, reconnect: bool = True) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    def is_ready(self) -> bool:
        raise NotImplementedError
