"""Bridge ``AlfredDiscordBot`` to the lifecycle's ``GatewayProtocol`` seam (#206).

``DiscordLifecycle`` drives the Discord connection through the ``GatewayProtocol``
contract (``connect(token)`` / ``close()`` / ``queue_depth``).
:class:`AlfredDiscordBot` exposes discord.py's ``login(token)`` (which raises
EARLY — ``LoginFailure`` — on bad credentials) and ``connect(reconnect=...)``
(which BLOCKS until the gateway disconnects), plus ``close()``.

Fail-loud ownership (C1). The naive shape — ``create_task(bot.start(token))`` with
no done-callback — swallows BOTH classes of failure: a startup ``LoginFailure``
and a runtime ``ConnectionClosed`` / ``PrivilegedIntentsRequired`` both raise
INSIDE the orphan task and are silently discarded, so ``lifecycle.start`` returns
``ok=True`` for a bot that will never connect and no ``adapter.crashed`` is
emitted. This adapter closes both holes:

* :meth:`connect` ``await``\\s ``login`` SYNCHRONOUSLY, so a credential failure
  surfaces as :class:`GatewayError` to ``lifecycle.start`` (→ ``ok=False``)
  BEFORE the detached loop starts;
* the detached ``connect`` task carries a done-callback that routes any
  non-cancelled exception through the bot's crash emitter — emitting
  ``adapter.crashed`` so the supervisor breaker can trip — instead of dropping
  it on the floor.

The adapter holds no global state; it owns the one background task for its bot's
lifetime and cancels nothing the bot does not already own.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Protocol

import structlog

from plugins.alfred_discord.lifecycle import GatewayError

_log = structlog.get_logger(__name__)


class _CrashForwarderLike(Protocol):
    """The crash emitter the bot exposes (routes uncaught task errors)."""

    def handle_crash(self, exc: BaseException) -> None: ...


class _BotLike(Protocol):
    """The subset of ``AlfredDiscordBot`` the adapter drives."""

    async def login(self, token: str) -> None: ...

    async def connect(self, *, reconnect: bool = True) -> None: ...

    async def close(self) -> None: ...

    @property
    def crash_forwarder(self) -> _CrashForwarderLike: ...


class DiscordGatewayAdapter:
    """Adapts a discord.py bot's ``login``/``connect``/``close`` to ``GatewayProtocol``."""

    def __init__(self, *, bot: _BotLike) -> None:
        self._bot = bot
        self._task: asyncio.Task[None] | None = None

    async def connect(self, token: str) -> None:
        """Log in (surfacing failure), then run the gateway loop on a background task.

        ``login`` is awaited inline so a ``LoginFailure`` (or any other login
        error) surfaces to ``lifecycle.start`` as :class:`GatewayError` and the
        lifecycle reports ``ok=False`` — the detached loop never starts for a bot
        that cannot authenticate (C1). Once logged in, ``connect`` runs detached
        (it blocks until disconnect); its done-callback routes a runtime crash
        through the crash emitter.
        """
        try:
            await self._bot.login(token)
        except Exception as exc:
            # Translate ANY login failure into the GatewayProtocol's typed
            # GatewayError so the lifecycle's secret-free ``ok=False`` path fires.
            # The token is NEVER in the re-raised message (we raise from the
            # class, not str(exc)), keeping the redaction contract trivial.
            _log.error(
                "comms.gateway.login_failed",
                adapter="discord",
                error_class=type(exc).__name__,
            )
            raise GatewayError("discord gateway login failed") from exc

        self._task = asyncio.create_task(self._bot.connect(reconnect=True))
        self._task.add_done_callback(self._on_connect_task_done)
        # Yield once so the connect task begins before ``connect`` returns.
        await asyncio.sleep(0)
        _log.info("comms.gateway.connecting", adapter="discord")

    def _on_connect_task_done(self, task: asyncio.Task[None]) -> None:
        """Route a non-cancelled connect-task exception through the crash emitter.

        A cancelled task (normal teardown via :meth:`close`) is NOT a crash. Any
        other exception that escaped the detached gateway loop is terminal: the
        crash emitter emits ``adapter.crashed`` + exits so the supervisor trips.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        _log.error(
            "comms.gateway.connect_task_crashed",
            adapter="discord",
            error_class=type(exc).__name__,
        )
        self._bot.crash_forwarder.handle_crash(exc)

    async def close(self) -> int:
        """Close the bot + await the background task; return the flushed count."""
        await self._bot.close()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        return 0

    @property
    def queue_depth(self) -> int:
        """In-flight outbound depth — zero until a real outbound buffer is wired."""
        return 0


__all__ = ["DiscordGatewayAdapter"]
