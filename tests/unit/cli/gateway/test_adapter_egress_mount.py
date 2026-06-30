"""``alfred gateway start`` mounts the Discord-adapter AF_UNIX egress listener (Spec C G7-4, #333).

The gateway is the sole external egress plane for adapters, so its start co-runs the
Discord-adapter :class:`alfred.gateway.egress_proxy.EgressForwardProxy` (bound to the
``DISCORD_EGRESS_SOCKET_PATH`` AF_UNIX socket) as a FOURTH sibling task alongside the
provider CONNECT proxy, the mode-(b) tool-egress relay, and the gateway process, under one
``asyncio.TaskGroup``.

Like the relay, the adapter proxy is **fail-closed**: a bind ``OSError`` maps to the typed
:class:`alfred.egress.errors.EgressAdapterProxyUnavailableError` (a subtype of
``IOPlaneUnavailableError``, caught BEFORE the base class), rendering a DISTINCT adapter
refusal line + exit code 9 — never the CONNECT proxy's ``egress_proxy_bind_failed`` line.

The process / proxy / relay / adapter-proxy are all replaced with doubles so these are
pure-wiring tests (no real socket bind).
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
from typer.testing import CliRunner

import alfred.cli.gateway._commands as c
from alfred.cli.gateway import gateway_app
from alfred.i18n import t


def test_adapter_exit_code_is_nine_and_distinct() -> None:
    """``_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED`` must be 9 and distinct from 7 and 8."""
    assert c._EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED == 9
    assert (
        len(
            {
                c._EXIT_EGRESS_PROXY_BIND_FAILED,
                c._EXIT_EGRESS_RELAY_BIND_FAILED,
                c._EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED,
            }
        )
        == 3
    ), "Exit codes 7, 8, and 9 must all be distinct"


def test_adapter_except_precedes_io_plane() -> None:
    """The ``except EgressAdapterProxyUnavailableError`` clause (subtype) must appear
    BEFORE ``except IOPlaneUnavailableError`` in ``start_gateway``'s handler block.

    The guard is on the CLAUSE position (``except EgressAdapterProxyUnavailableError``),
    not the bare class name (which also appears on the import line and would give a
    vacuous result). Non-vacuous: the ``except`` prefix ensures we match the handler
    clause, not the import.
    """
    src = inspect.getsource(c.start_gateway)
    adapter_clause = "except EgressAdapterProxyUnavailableError"
    io_plane_clause = "except IOPlaneUnavailableError"
    assert adapter_clause in src, f"'{adapter_clause}' clause missing from start_gateway source"
    assert io_plane_clause in src, f"'{io_plane_clause}' clause missing from start_gateway source"
    a = src.index(adapter_clause)
    i = src.index(io_plane_clause)
    assert a < i, (
        "EgressAdapterProxyUnavailableError except-clause (subtype) must precede "
        "IOPlaneUnavailableError — subtype must be caught first"
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal env for ``start_gateway``.

    ``_resolve_hosted_adapter_ids()`` constructs ``Settings()``, which requires the
    provider key + environment. The adapter proxy itself never constructs Settings.
    Relay / proxy resolvers' defaults are pinned; the hosted-adapter set is cleared so
    the test does not divert to ``config_failed``.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    for var in (
        "ALFRED_EGRESS_PROXY_PORT",
        "ALFRED_EGRESS_PROXY_BIND",
        "ALFRED_DEEPSEEK_BASE_URL",
        "ALFRED_EGRESS_RELAY_PORT",
        "ALFRED_EGRESS_RELAY_BIND",
        "ALFRED_TOOL_EGRESS_ALLOWLIST",
        "ALFRED_CANARY_TOKENS",
        "ALFRED_COMMS_ENABLED_ADAPTERS",
        "ALFRED_DISCORD_EGRESS_ALLOWLIST",
    ):
        monkeypatch.delenv(var, raising=False)


def _patch_process_proxy_and_relay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Doubles for the OTHER three co-run siblings whose ``serve`` / ``run`` return at once."""

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            del shutdown_event

        async def run(self) -> None:
            return None

    class _FakeProxy:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event

    class _FakeRelay:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr("alfred.gateway.egress_proxy.EgressForwardProxy", _FakeProxy)
    monkeypatch.setattr("alfred.gateway.egress_relay.EgressRelay", _FakeRelay)


def test_start_mounts_the_adapter_egress_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``start`` builds the adapter egress proxy via ``build_adapter_egress_proxy``
    and serves it as a fourth sibling task in the TaskGroup."""
    _patch_process_proxy_and_relay(monkeypatch)
    served: list[bool] = []

    class _FakeAdapterProxy:
        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            served.append(True)

    monkeypatch.setattr(
        "alfred.gateway.adapter_egress_listener.build_adapter_egress_proxy",
        lambda **_kw: _FakeAdapterProxy(),
    )

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert served == [True], "adapter egress proxy must have been served in the TaskGroup"


def test_start_adapter_bind_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An adapter bind ``OSError`` refuses the start with a friendly adapter-specific line
    + a DISTINCT exit code 9, never the CONNECT proxy's ``egress_proxy_bind_failed`` line
    nor the relay's ``egress_relay_bind_failed`` line."""
    _patch_process_proxy_and_relay(monkeypatch)

    class _BindFailingAdapterProxy:
        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("discord egress socket already in use")

    monkeypatch.setattr(
        "alfred.gateway.adapter_egress_listener.build_adapter_egress_proxy",
        lambda **_kw: _BindFailingAdapterProxy(),
    )

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == c._EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.egress_adapter_bind_failed") in result.stdout
    # DISTINCT from the provider CONNECT proxy's bind-failed line.
    assert t("gateway.start.egress_proxy_bind_failed") not in result.stdout
    # DISTINCT from the relay's bind-failed line.
    assert t("gateway.start.egress_relay_bind_failed") not in result.stdout


def test_serve_adapter_egress_failclosed_maps_oserror() -> None:
    """``serve_adapter_egress_failclosed`` maps a bind ``OSError`` to
    ``EgressAdapterProxyUnavailableError`` — a clean unwrapped probe of the mapping,
    independent of the TaskGroup (mirrors the relay's equivalent test)."""
    from alfred.egress.errors import EgressAdapterProxyUnavailableError
    from alfred.gateway.adapter_egress_listener import serve_adapter_egress_failclosed

    class _BindFailingProxy:
        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("EADDRINUSE")

    with pytest.raises(EgressAdapterProxyUnavailableError):
        # _BindFailingProxy structurally satisfies the _EgressProxyLike Protocol that
        # serve_adapter_egress_failclosed's `proxy` param is typed against, so no
        # suppression is needed (mirrors test_adapter_egress_listener.py's _BoomProxy).
        asyncio.run(serve_adapter_egress_failclosed(_BindFailingProxy(), asyncio.Event()))
