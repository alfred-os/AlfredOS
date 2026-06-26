"""``alfred gateway start`` mounts the L7 CONNECT egress forward-proxy (Spec C G7-1b, #333).

The gateway is the sole external egress plane, so its start co-runs the
:class:`alfred.gateway.egress_proxy.EgressForwardProxy` alongside the
:class:`alfred.gateway.process.GatewayProcess` under a single ``asyncio.TaskGroup``.

Unlike the metrics server (loud-and-continue), the proxy is **fail-closed**: a bind
``OSError`` is mapped to a friendly :class:`alfred.egress.errors.IOPlaneUnavailableError`
refusal (a distinct exit code + a distinct operator line), which REFUSES the start — the
gateway then crash-loops under ``restart: unless-stopped`` (the intended I/O-plane posture:
the proxy IS the gateway's reason to exist).

Both the process and the proxy are replaced with doubles so these are pure-wiring tests
(no real socket bind). The proxy double's ``serve`` returns immediately so the co-run
TaskGroup unwinds; the bind-failure double raises ``OSError`` from ``serve``.
"""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app
from alfred.i18n import t


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Settings() (the proxy allowlist source) needs the provider key + environment.
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # Pin the proxy port/bind defaults so the resolvers never read a polluted env.
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_PORT", raising=False)
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_BIND", raising=False)


def _patch_gateway_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``GatewayProcess`` with a double whose ``run`` returns at once."""

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            del shutdown_event

        async def run(self) -> None:
            return None

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)


def test_start_mounts_egress_proxy_with_settings_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``start`` builds an ``EgressForwardProxy`` from the live allowlist and serves it.

    The proxy is constructed with the SAME ``provider_egress_allowlist`` the in-core
    EgressClient references (so the gateway cannot drift from the core's destination set)
    and its ``serve`` is awaited concurrently with the gateway process.
    """
    captured: dict[str, object] = {}
    _patch_gateway_process(monkeypatch)

    class _FakeProxy:
        def __init__(
            self,
            *,
            allowlist: frozenset[tuple[str, int]],
            bind_host: str,
            port: int,
            audit: object,
            **_kw: object,
        ) -> None:
            captured["allowlist"] = allowlist
            captured["bind_host"] = bind_host
            captured["port"] = port
            captured["audit"] = audit

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            captured["served"] = True

    monkeypatch.setattr("alfred.gateway.egress_proxy.EgressForwardProxy", _FakeProxy)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("served") is True
    allowlist = captured.get("allowlist")
    assert isinstance(allowlist, frozenset)
    # The live provider allowlist: the Anthropic SDK default + the DeepSeek base-URL host.
    assert ("api.anthropic.com", 443) in allowlist
    assert ("api.deepseek.com", 443) in allowlist
    assert captured.get("port") == 8889  # the resolved default proxy port
    assert callable(captured.get("audit"))


def test_start_egress_proxy_bind_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy bind ``OSError`` refuses the start with a friendly egress-proxy line.

    Fail-closed (contrast the metrics server's loud-and-continue): the proxy is the
    gateway's reason to exist, so a bind failure maps to ``IOPlaneUnavailableError`` and a
    DISTINCT operator message + non-zero exit — never the client-socket ``bind_failed``
    line (which would mislabel the cause), and never a raw traceback.
    """
    _patch_gateway_process(monkeypatch)

    class _BindFailingProxy:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event
            raise OSError("egress proxy address already in use")

    monkeypatch.setattr("alfred.gateway.egress_proxy.EgressForwardProxy", _BindFailingProxy)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    # A friendly line rendered, not a bare traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.egress_proxy_bind_failed") in result.stdout
    # DISTINCT from the client-socket bind-failed line (different cause, different fix).
    assert t("gateway.start.bind_failed") not in result.stdout
