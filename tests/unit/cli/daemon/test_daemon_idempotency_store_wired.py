"""PR-S4 G0: the daemon builds + injects the durable accept-once store on inbound.

The Spec-A G0 cut: the live daemon inbound path constructs ONE
``PostgresInboundIdempotencyStore`` in ``_build_comms_boot_graph`` (over the
shared cached engine, the ``audit_writer`` shape) and injects it into every
per-adapter ``InboundMessageHandler`` so a replayed comms frame short-circuits
before any side effect.

This test proves the daemon CONSTRUCTS and INJECTS that store on the live boot
path. It is modelled exactly on
``test_daemon_promoter_wiring.py::test_enabled_empty_set_adapter_wires_none_promoter``:
spy ``InboundMessageHandler.__init__`` kwargs via ``monkeypatch``, boot the daemon
through ``CliRunner().invoke(daemon_app, ["start"])`` with ``_patch_comms_seams``,
and assert the captured ``idempotency_store`` kwarg is a non-``None``
``PostgresInboundIdempotencyStore``. The commit-once / replay-short-circuit
semantics themselves live in ``tests/unit/comms_mcp/test_inbound_idempotency_guard.py``
and ``tests/integration/test_inbound_idempotency_postgres.py``; this file proves
only the wiring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.comms_mcp.handlers import InboundMessageHandler
from alfred.hooks.registry import HookRegistry
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import (
    _ENABLED_ADAPTER,
    _patch_comms_seams,
    quarantine_registry,
)

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


def test_enabled_adapter_wires_idempotency_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The enabled adapter boots with a ``PostgresInboundIdempotencyStore`` injected.

    Proves the daemon builds ONE durable accept-once store in the comms boot graph
    and threads it into the per-adapter inbound handler (Spec A G0).
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    captured: list[Any] = []
    original_init = InboundMessageHandler.__init__

    def _spy_init(self: Any, **kwargs: Any) -> None:
        captured.append(kwargs.get("idempotency_store"))
        original_init(self, **kwargs)

    monkeypatch.setattr(InboundMessageHandler, "__init__", _spy_init)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Exactly one inbound handler built, wired with a real durable accept-once store.
    assert len(captured) == 1
    assert isinstance(captured[0], PostgresInboundIdempotencyStore)
