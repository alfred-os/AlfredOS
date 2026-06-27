"""``alfred gateway start`` mounts the mode-(b) tool-egress relay (Spec C G7-2b, #333).

The gateway is the sole maker of inspectable tool HTTP requests, so its start co-runs
the :class:`alfred.gateway.egress_relay.EgressRelay` as a THIRD sibling task alongside
the CONNECT proxy + the gateway process, under one ``asyncio.TaskGroup``.

Like the proxy, the relay is **fail-closed**: a bind ``OSError`` maps to the typed
:class:`alfred.egress.errors.EgressRelayUnavailableError` (a subtype of
``IOPlaneUnavailableError``, caught first), rendering a DISTINCT relay refusal line +
exit code — never the CONNECT proxy's ``egress_proxy_bind_failed`` line.

The process / proxy / relay are all replaced with doubles so these are pure-wiring
tests (no real socket bind). The relay config is derived from public env (never the
secret-requiring Settings — ADR-0036).
"""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app
from alfred.i18n import t


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    # _resolve_hosted_adapter_ids() (in start) constructs Settings(), which needs the
    # provider key + environment. The relay itself NEVER constructs Settings.
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # Pin the relay/proxy resolvers' defaults so they never read a polluted env.
    for var in (
        "ALFRED_EGRESS_PROXY_PORT",
        "ALFRED_EGRESS_PROXY_BIND",
        "ALFRED_DEEPSEEK_BASE_URL",
        "ALFRED_EGRESS_RELAY_PORT",
        "ALFRED_EGRESS_RELAY_BIND",
        "ALFRED_TOOL_EGRESS_ALLOWLIST",
        "ALFRED_CANARY_TOKENS",
    ):
        monkeypatch.delenv(var, raising=False)


def _patch_process_and_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Doubles for the OTHER two co-run siblings whose ``serve`` / ``run`` return at once."""

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

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr("alfred.gateway.egress_proxy.EgressForwardProxy", _FakeProxy)


def test_start_mounts_the_relay_with_the_relay_audit_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``start`` builds an ``EgressRelay`` from public env + the relay audit sink and
    serves it concurrently with the proxy + the gateway process."""
    captured: dict[str, object] = {}
    _patch_process_and_proxy(monkeypatch)

    class _FakeRelay:
        def __init__(
            self,
            *,
            tool_allowlist: frozenset[tuple[str, int]],
            dlp: object,
            audit: object,
            bind_host: str,
            port: int,
            **_kw: object,
        ) -> None:
            captured["tool_allowlist"] = tool_allowlist
            captured["dlp"] = dlp
            captured["audit"] = audit
            captured["bind_host"] = bind_host
            captured["port"] = port

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            captured["served"] = True

    monkeypatch.setattr("alfred.gateway.egress_relay.EgressRelay", _FakeRelay)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("served") is True
    assert captured.get("port") == 8890  # the resolved default relay port
    assert isinstance(captured.get("tool_allowlist"), frozenset)
    # The EXACT relay audit sink (the payload-blind field-allowlist guard), not just
    # "some callable" — a regression to a stubbed logger must fail here.
    from alfred.gateway.egress_relay_audit import record_egress_relay

    assert captured.get("audit") is record_egress_relay


def test_start_relay_bind_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relay bind ``OSError`` refuses the start with a friendly relay-specific line
    + a DISTINCT exit, never the CONNECT proxy's bind-failed line."""
    _patch_process_and_proxy(monkeypatch)

    class _BindFailingRelay:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("relay address already in use")

    monkeypatch.setattr("alfred.gateway.egress_relay.EgressRelay", _BindFailingRelay)

    result = CliRunner().invoke(gateway_app, ["start"])

    from alfred.cli.gateway._commands import _EXIT_EGRESS_RELAY_BIND_FAILED

    assert result.exit_code == _EXIT_EGRESS_RELAY_BIND_FAILED
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.egress_relay_bind_failed") in result.stdout
    # DISTINCT from the CONNECT proxy's bind-failed line (different plane, different fix).
    assert t("gateway.start.egress_proxy_bind_failed") not in result.stdout


def test_serve_egress_relay_failclosed_maps_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fail-closed wrapper maps a bind ``OSError`` to ``EgressRelayUnavailableError``
    (a clean unwrapped probe of the mapping, independent of the TaskGroup)."""
    from alfred.cli.gateway._commands import _serve_egress_relay_failclosed
    from alfred.egress.errors import EgressRelayUnavailableError

    class _BindFailingRelay:
        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("EADDRINUSE")

    with pytest.raises(EgressRelayUnavailableError):
        asyncio.run(_serve_egress_relay_failclosed(_BindFailingRelay(), asyncio.Event()))  # type: ignore[arg-type]
