"""Pin stdlib logging to stderr for stdout-protocol subprocess entrypoints.

PR-S4-11c-2b0 BUG-1. Two AlfredOS subprocess entrypoints speak a
machine-readable protocol on **stdout** and MUST keep fd 1 byte-pure:

* :mod:`alfred.plugins.manifest_reader` — its ``--policy-to-bwrap-flags`` /
  ``--read-sandbox`` / ``--read-environment`` modes print parseable values on
  stdout. ``bin/alfred-plugin-launcher.sh`` captures that stdout and turns each
  line into a ``bwrap`` flag. A stray log line on stdout becomes a bogus bwrap
  argument (it once became the bwrap *exec target*).
* :mod:`alfred.security.quarantine_child.__main__` — the bwrapped quarantine
  child writes length-prefixed JSON-RPC reply frames on stdout. A log line there
  corrupts the wire the host transport reads.

stdlib ``logging`` with no handler configured routes through
``logging.lastResort``, which already targets stderr — but that is global mutable
state any imported module can repoint at stdout, and the destination is only
correct *by default*. This helper makes it correct *by construction*: it installs
a single :class:`logging.StreamHandler` bound to ``sys.stderr`` on the root logger
and removes any handler that points at ``sys.stdout``, so nothing the process logs
can reach fd 1.

Dependency-free (stdlib only): the quarantine child's import closure is bounded
to schemas + ``ProviderCapability`` (ADR-0030), so this module must not pull in
``structlog`` or any privileged host module. The richer structlog-to-stderr helper
for comms plugins lives in :mod:`alfred.comms_mcp.plugin_logging`; this is its
stdlib sibling for the two non-structlog entrypoints.
"""

from __future__ import annotations

import logging
import sys

__all__ = ["configure_stderr_logging"]


def configure_stderr_logging(*, level: int = logging.WARNING) -> None:
    """Route ALL stdlib logging to ``sys.stderr``; clear any stdout handler.

    Idempotent: re-pins the same single stderr handler on the root logger and
    strips any pre-existing handler whose stream is ``sys.stdout`` (the only
    stream that would corrupt the entrypoint's machine-readable output). Call it
    at the very top of the entrypoint — before any import that may log at import
    time (e.g. the i18n translator's missing-catalog warning) and before the
    first byte of stdout protocol.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        stream = getattr(handler, "stream", None)
        if stream is sys.stdout:
            root.removeHandler(handler)
    stderr_handler = logging.StreamHandler(sys.stderr)
    if not any(
        getattr(h, "stream", None) is sys.stderr and isinstance(h, logging.StreamHandler)
        for h in root.handlers
    ):
        root.addHandler(stderr_handler)
    root.setLevel(level)
