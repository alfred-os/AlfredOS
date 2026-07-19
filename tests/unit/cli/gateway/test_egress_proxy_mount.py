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
    # Pin the proxy/allowlist resolvers' defaults so they never read a polluted env.
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_PORT", raising=False)
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_BIND", raising=False)
    monkeypatch.delenv("ALFRED_DEEPSEEK_BASE_URL", raising=False)
    # start_gateway() resolves hosted adapters (via Settings) BEFORE building the
    # proxy/relay, so an ambient value would divert these tests to config_failed (CR
    # review). The relay mount (third sibling task) is also patched per-test.
    monkeypatch.delenv("ALFRED_COMMS_ENABLED_ADAPTERS", raising=False)


def _patch_gateway_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``GatewayProcess`` with a double whose ``run`` returns at once, the
    mode-(b) ``EgressRelay`` with a double whose ``serve`` returns at once (so the
    co-run TaskGroup unwinds without binding the relay's real port — G7-2b), and
    ``build_adapter_egress_proxy`` with a factory that returns a no-op double (so
    the Discord AF_UNIX socket is never bound — G7-4)."""

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            del shutdown_event

        async def run(self) -> None:
            return None

    class _FakeRelay:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event

    class _FakeAdapterProxy:
        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr("alfred.gateway.egress_relay.EgressRelay", _FakeRelay)
    monkeypatch.setattr(
        "alfred.gateway.adapter_egress_listener.build_adapter_egress_proxy",
        lambda **_kw: _FakeAdapterProxy(),
    )


def test_start_mounts_egress_proxy_with_provider_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``start`` builds an ``EgressForwardProxy`` from the provider allowlist and serves it.

    The allowlist is derived from the public ``ALFRED_DEEPSEEK_BASE_URL`` (the SAME value
    compose threads to the core's Settings, so the gateway cannot drift from the core's
    destination set) and its ``serve`` is awaited concurrently with the gateway process.
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
            handshake_timeout_s: float = 10.0,
            **_kw: object,
        ) -> None:
            captured["allowlist"] = allowlist
            captured["bind_host"] = bind_host
            captured["port"] = port
            captured["audit"] = audit
            captured["handshake_timeout_s"] = handshake_timeout_s

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
    # The provider plane raises the handshake idle timeout to 22s (spec §21.5 / ADR-0052) so a
    # late-retry pre-brokered socket survives; the Discord/relay planes keep the 10s default.
    # Pinned to the live constant so the construction site cannot drift from the merge-gate value.
    from alfred.gateway.egress_proxy import _PROVIDER_HANDSHAKE_TIMEOUT_S

    assert captured.get("handshake_timeout_s") == _PROVIDER_HANDSHAKE_TIMEOUT_S == 22.0
    # The EXACT field-allowlisted audit sink (the payload-blind guard for PRD §7.1), not just
    # "some callable" — a regression to a stubbed logger must fail here.
    from alfred.gateway.egress_audit import record_egress_connect

    assert captured.get("audit") is record_egress_connect


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

    # The DEDICATED egress-proxy bind exit code (distinct from the client-socket bind / core
    # / config refusals) so an operator script can branch on the egress-plane outage.
    from alfred.cli.gateway._commands import _EXIT_EGRESS_PROXY_BIND_FAILED

    assert result.exit_code == _EXIT_EGRESS_PROXY_BIND_FAILED
    # A friendly line rendered, not a bare traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.egress_proxy_bind_failed") in result.stdout
    # DISTINCT from the client-socket bind-failed line (different cause, different fix).
    assert t("gateway.start.bind_failed") not in result.stdout


def test_reraise_first_meaningful_flattens_nested_cancellation_group() -> None:
    """A leading pure-cancellation SUBGROUP must not mask a real sibling leaf (err-002).

    The flat single-leaf case is what the TaskGroup produces in practice; this pins the
    defensive nested-flatten so a future change that nests groups can't silently swallow the
    real fault.
    """
    from alfred.cli.gateway._commands import _reraise_first_meaningful

    real = RuntimeError("the real fault")
    group = BaseExceptionGroup(
        "outer",
        [
            BaseExceptionGroup("inner-cancellations", [asyncio.CancelledError()]),
            real,
        ],
    )
    with pytest.raises(RuntimeError, match="the real fault"):
        _reraise_first_meaningful(group)


def test_reraise_first_meaningful_reraises_a_pure_cancellation_group() -> None:
    """A group with ONLY cancellations (no real fault) is re-raised unchanged."""
    from alfred.cli.gateway._commands import _reraise_first_meaningful

    group = BaseExceptionGroup(
        "all-cancellations", [asyncio.CancelledError(), asyncio.CancelledError()]
    )
    with pytest.raises(BaseExceptionGroup):
        _reraise_first_meaningful(group)
