"""The Discord adapter server constructs the lifecycle with the fd-3 token source.

Under the gateway-hosted spawn model (Spec B G6-5, #288) the core injects the bot
token over LITERAL fd 3 — the adapter no longer self-brokers it. This pins the
server-construction contract:

* ``_build_server`` wires ``DiscordLifecycle`` with a ``Fd3TokenSource`` (the
  literal-fd-3 reader), NOT a broker;
* no broker-token dependency remains in the server module (no ``_EnvBroker``,
  and the ``DiscordLifecycle`` construction passes no ``broker=``).
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import plugins.alfred_discord.server as server_module
from plugins.alfred_discord.lifecycle import DiscordLifecycle, Fd3TokenSource


def test_build_server_wires_fd3_token_source_into_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    real_init = DiscordLifecycle.__init__

    def _spy_init(self: DiscordLifecycle, **kwargs: object) -> None:
        captured.update(kwargs)
        real_init(self, **kwargs)  # type: ignore[arg-type]

    # `_build_server` constructs the REAL idempotency ledger. Without this
    # override `idempotency_db_path()` falls back to a private temp dir OUTSIDE
    # `tmp_path`, so the db plus its -wal/-shm pair persist between runs on a
    # developer box and leak state across tests. Pin it into tmp_path.
    monkeypatch.setenv("ALFRED_DISCORD_RUNTIME_DIR", str(tmp_path))

    original = DiscordLifecycle.__init__
    DiscordLifecycle.__init__ = _spy_init  # type: ignore[method-assign]
    try:
        server_module._build_server()
    finally:
        DiscordLifecycle.__init__ = original  # type: ignore[method-assign]

    assert "token_source" in captured
    assert isinstance(captured["token_source"], Fd3TokenSource)
    # A lingering broker-token injection would be a dual-source regression.
    assert "broker" not in captured


def test_server_module_has_no_broker_token_class() -> None:
    """No ``_EnvBroker`` (broker-token proxy) remains in the server module."""
    assert not hasattr(server_module, "_EnvBroker")
    source = inspect.getsource(server_module)
    assert "broker=" not in source
