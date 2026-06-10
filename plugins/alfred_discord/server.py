#!/usr/bin/env python3
"""Discord adapter MCP stdio server entry point (PR-S4-9 #206).

The host transport speaks line-delimited JSON-RPC (matching
``alfred_comms_test`` / ``alfred_web_fetch`` / ``alfred_quarantined_llm``); the
ADR-0024 method names appear LITERALLY on the wire.

Host -> plugin requests this server answers:

* ``lifecycle.start``  -> :meth:`DiscordLifecycle.start` (opens the gateway via
  the :class:`DiscordGatewayAdapter`)
* ``lifecycle.stop``   -> :meth:`DiscordLifecycle.stop`
* ``adapter.health``   -> :meth:`DiscordLifecycle.health`
* ``outbound.message`` -> :meth:`OutboundDispatcher.dispatch` (the real
  idempotency-keyed send-path + comms-3 rate-limit ordering)

The plugin -> host notifications (``inbound.message``,
``adapter.binding_request``, ``adapter.rate_limit_signal``, ``adapter.crashed``)
are emitted by the gateway + Component-G emitters through the shared
:class:`StdoutNotificationSink`. :func:`serve` assembles the full adapter and
wraps the stdio loop in the crash emitter so an uncaught exception emits
``adapter.crashed`` + exits 1 (tripping the host supervisor breaker).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

import structlog

from alfred.comms_mcp.plugin_logging import configure_stderr_json_logging
from alfred.comms_mcp.protocol import OutboundMessageRequest
from plugins.alfred_discord.crash_emitter import CrashEmitter
from plugins.alfred_discord.discord_gateway import AlfredDiscordBot
from plugins.alfred_discord.gateway_adapter import DiscordGatewayAdapter
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.lifecycle import DiscordLifecycle
from plugins.alfred_discord.notifications import StdoutNotificationSink
from plugins.alfred_discord.outbound_dispatcher import OutboundDispatcher
from plugins.alfred_discord.outbound_handler import OutboundHandler
from plugins.alfred_discord.rate_limit_emitter import RateLimitEmitter

_log = structlog.get_logger(__name__)

# ADR-0024 wire method names — host -> plugin requests.
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"
_METHOD_LIFECYCLE_STOP: Final[str] = "lifecycle.stop"
_METHOD_ADAPTER_HEALTH: Final[str] = "adapter.health"
_METHOD_OUTBOUND_MESSAGE: Final[str] = "outbound.message"


class DiscordServer:
    """Routes decoded JSON-RPC request frames to the four request handlers."""

    def __init__(
        self,
        *,
        lifecycle: DiscordLifecycle | None,
        outbound_dispatcher: OutboundDispatcher | None = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._outbound_dispatcher = outbound_dispatcher

    async def dispatch(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Route one request frame to its handler; return the response frame.

        Returns ``None`` only for a frame with no ``id`` AND a recognised
        notification method — none of the four request methods is a
        notification, so a well-formed request always yields a response. A
        malformed frame (missing/empty method) yields an ``Invalid Request``.
        """
        has_response_id = "id" in request
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if not isinstance(method, str) or not method:
            return _invalid_request(req_id if has_response_id else None)

        result = await self._handle(method, params)
        if result is None:
            return _method_not_found(method, req_id if has_response_id else None)

        response: dict[str, Any] = {"jsonrpc": "2.0", "result": result}
        if has_response_id:
            response["id"] = req_id
        return response

    async def _handle(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """Return the result body for ``method``, or ``None`` if unrecognised."""
        if method == _METHOD_OUTBOUND_MESSAGE:
            return await self._handle_outbound_message(params)
        if self._lifecycle is None:  # pragma: no cover - wired in production only
            msg = "lifecycle handlers require a wired DiscordLifecycle"
            raise RuntimeError(msg)
        if method == _METHOD_LIFECYCLE_START:
            return (await self._lifecycle.start()).model_dump(mode="json")
        if method == _METHOD_LIFECYCLE_STOP:
            return (await self._lifecycle.stop()).model_dump(mode="json")
        if method == _METHOD_ADAPTER_HEALTH:
            return self._lifecycle.health().model_dump(mode="json")
        return None

    async def _handle_outbound_message(self, params: dict[str, Any]) -> dict[str, Any]:
        """Parse the request + dispatch it through the real send-path.

        Returns the ``OutboundMessageResult`` discriminated-union dict. When no
        dispatcher is wired (a partially-constructed server), returns a typed
        ``terminal_failure`` so the host records a loud, structured refusal rather
        than a silent drop — ``detail_redacted`` carries no platform bytes.
        """
        if self._outbound_dispatcher is None:
            _log.warning("comms.outbound.unwired", adapter="discord")
            return {
                "outcome": "terminal_failure",
                "error_class": "OutboundDispatcherUnwired",
                "detail_redacted": "outbound dispatcher not wired",
            }
        request = OutboundMessageRequest.model_validate(params)
        result = await self._outbound_dispatcher.dispatch(request)
        return result.model_dump(mode="json")


# ---------------------------------------------------------------------------
# JSON-RPC envelope helpers
# ---------------------------------------------------------------------------


def _method_not_found(method: str, req_id: object) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _invalid_request(req_id: object) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32600, "message": "Invalid Request"},
    }


def _parse_error(detail: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "Parse error", "data": {"detail": detail}},
    }


async def _serve_stdin_stdout(server: DiscordServer) -> None:  # pragma: no cover - subprocess loop
    """MCP stdio loop: read JSON-RPC frames, answer requests.

    Covered end-to-end by integration tests that spawn this module as a
    subprocess; :meth:`DiscordServer.dispatch` carries the unit coverage.
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )

    def _emit(frame: dict[str, Any]) -> None:
        writer_transport.write((json.dumps(frame) + "\n").encode())

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit(_parse_error(str(exc)))
            continue
        if not isinstance(request, dict):
            _emit(_invalid_request(None))
            continue
        response = await server.dispatch(request)
        if response is not None:
            _emit(response)


_ADAPTER_ID: Final[str] = "discord"
_BROKER_KEY: Final[str] = "discord_bot_token"


# The bwrap sandbox's ONLY writable mount (M1). The Discord-adapter policy
# (config/sandbox/discord-adapter.linux.bwrap.policy) mounts an ephemeral tmpfs
# here; EVERY other path in the sandbox is read-only, so the idempotency store
# MUST live under this directory or ``sqlite3.connect`` hits a read-only FS and
# crashes the plugin on first outbound.
_SANDBOX_TMPFS_ROOT: Final[str] = "/run/alfred/discord"


def idempotency_db_path() -> Path:
    """Resolve the on-disk idempotency store path under the sandbox tmpfs (M1).

    The real bwrap policy mounts a writable tmpfs at :data:`_SANDBOX_TMPFS_ROOT`
    and makes every other path read-only, so the production store lives directly
    under that mount. ``ALFRED_DISCORD_RUNTIME_DIR`` overrides the root (the
    sandbox launcher / a test may point it elsewhere); a bare-shell fallback to a
    private temp dir keeps the path deterministic and writable when neither the
    override nor the tmpfs is mounted, with ``0700`` perms so a world-readable
    ``/tmp`` fallback never exposes the ledger (L3).
    """
    override = os.environ.get("ALFRED_DISCORD_RUNTIME_DIR")
    if override:
        return Path(override) / "idempotency.db"
    tmpfs = Path(_SANDBOX_TMPFS_ROOT)
    if tmpfs.is_dir() and os.access(tmpfs, os.W_OK):
        return tmpfs / "idempotency.db"
    # Bare-shell fallback (no sandbox tmpfs, no override): a private 0700 dir
    # under the system temp root so the ledger is never world-readable (L3).
    fallback = Path(tempfile.gettempdir()) / "alfred" / "plugin-alfred.discord"
    fallback.mkdir(parents=True, exist_ok=True)
    fallback.chmod(0o700)
    return fallback / "idempotency.db"


class _EnvBroker:
    """Broker proxy: the host substitutes the resolved secret at the dispatch
    boundary (spec §7.8), so the adapter reads the resolved value by name. The
    plugin never holds a hardcoded credential.
    """

    def get(self, name: str) -> str:  # pragma: no cover - production secret path
        value = os.environ.get(name)
        if value is None:
            msg = f"secret {name!r} not provided by the broker"
            raise RuntimeError(msg)
        return value


class _BotTargetResolver:  # pragma: no cover - requires a live discord.py client
    """Resolve a send target from the live bot per ``addressing_mode``."""

    def __init__(self, bot: AlfredDiscordBot) -> None:
        self._bot = bot

    async def resolve(self, target_platform_id: str, addressing_mode: str) -> Any:
        if addressing_mode == "dm":
            return await self._bot.fetch_user(int(target_platform_id))
        return await self._bot.fetch_channel(int(target_platform_id))


def _build_server(
    sink: StdoutNotificationSink | None = None,
) -> DiscordServer:  # pragma: no cover - live-gateway assembly
    """Assemble the full adapter: gateway + lifecycle + outbound dispatcher.

    The bot connects via the :class:`DiscordGatewayAdapter` (which the lifecycle
    drives as its ``GatewayProtocol``); the outbound dispatcher fronts the
    idempotency-keyed send-path; the crash emitter wraps the main loop in
    :func:`_serve`.

    ``sink`` lets the caller pass the SAME stateless notification sink it uses for
    the top-level crash emitter, so the entrypoint does not instantiate two.
    """
    if sink is None:
        sink = StdoutNotificationSink()
    crash = CrashEmitter(adapter_id=_ADAPTER_ID, sink=sink)
    bot = AlfredDiscordBot(
        adapter_id=_ADAPTER_ID,
        bot_user_id=0,  # resolved on on_ready from the logged-in bot user
        sink=sink,
        crash_emitter=crash,
        channel_listen_set=frozenset(),
    )
    gateway = DiscordGatewayAdapter(bot=bot)
    lifecycle = DiscordLifecycle(broker=_EnvBroker(), gateway=gateway)

    store = IdempotencyStore(db_path=idempotency_db_path())
    handler = OutboundHandler(resolver=_BotTargetResolver(bot), store=store)
    rate_limit_emitter = RateLimitEmitter(adapter_id=_ADAPTER_ID, sink=sink)
    dispatcher = OutboundDispatcher(handler=handler, rate_limit_emitter=rate_limit_emitter)

    return DiscordServer(lifecycle=lifecycle, outbound_dispatcher=dispatcher)


async def serve() -> None:  # pragma: no cover - process entrypoint
    """Run the adapter's stdio loop, forwarding an uncaught crash to the emitter.

    Structlog is pinned to stderr-JSON before the loop (review F4) so stdout
    carries ONLY line-delimited JSON-RPC frames — a stray console-rendered log
    line on stdout would interleave with the wire frames the host reads.
    """
    configure_stderr_json_logging()
    sink = StdoutNotificationSink()
    server = _build_server(sink)
    crash = CrashEmitter(adapter_id=_ADAPTER_ID, sink=sink)
    try:
        await _serve_stdin_stdout(server)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        crash.handle_crash(exc)


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    asyncio.run(serve())
