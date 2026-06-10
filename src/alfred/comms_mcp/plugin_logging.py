"""Stderr-only JSON logging for comms-MCP stdio plugins (PR-S4-10 review F4, #206).

A comms-MCP stdio plugin speaks line-delimited JSON-RPC *frames* on **stdout**;
the host's :class:`alfred.plugins.stdio_transport` reader treats every stdout
line as a wire frame. A plugin subprocess that leaves ``structlog`` on its
default console renderer writes human-readable log lines to **stdout** too,
interleaving them with the wire frames and corrupting the channel.

This module configures ``structlog`` to render JSON to **stderr** so stdout
carries only JSON-RPC frames. It mirrors
:func:`alfred.cli._bootstrap.configure_logging`'s processor chain (level +
ISO-UTC timestamp + JSON renderer) but pins the sink to stderr via an explicit
:class:`structlog.PrintLoggerFactory`. Every plugin ``serve()`` entry point
calls it once before entering the stdio loop.

It is deliberately dependency-free (no ``SecretBroker``): the only stdio
plugins are the operator-local TUI (no secrets) and the Discord relay (whose
secret material never reaches a log call — credentials are fetched at the
broker boundary host-side, not in the plugin). A plugin that DOES log
secret-derived values must route through the host redactor, not this helper.
"""

from __future__ import annotations

import sys

import structlog


def configure_stderr_json_logging(*, level: int = 20) -> None:
    """Configure ``structlog`` to render JSON to stderr (default level INFO=20).

    Idempotent in effect — ``structlog.configure`` replaces the global config,
    so a second call simply re-pins the same chain. ``cache_logger_on_first_use``
    is left FALSE so a logger bound before this call (e.g. a module-level
    ``structlog.get_logger(__name__)``) still observes the new configuration on
    its next event rather than caching the pre-config console renderer.
    """
    structlog.configure(
        processors=[
            # Surface contextvars bound via ``structlog.contextvars`` (e.g. the
            # TUI server's launcher-supplied ``adapter_id`` self-id, review F7).
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=False,
    )


__all__ = ["configure_stderr_json_logging"]
