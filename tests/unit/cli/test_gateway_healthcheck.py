"""`alfred gateway healthcheck` — two-tier liveness/readiness probe (G6-0)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    def _fake_fetch(port: int) -> str:
        if text is None:
            raise OSError("connection refused")
        return text

    # healthcheck_gateway imports fetch_metrics_text LAZILY (inside the function body,
    # same perf-001 rationale as start_gateway's lazy metrics_server import below), so
    # the patch target is the SOURCE module, not `_commands` — a module-attribute patch
    # on `_commands` would never be seen by the function-local import.
    monkeypatch.setattr("alfred.observability.metrics_server.fetch_metrics_text", _fake_fetch)


def test_healthcheck_registered() -> None:
    result = CliRunner().invoke(gateway_app, ["--help"])
    assert result.exit_code == 0
    assert "healthcheck" in result.stdout


def test_healthy_when_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_core_down_but_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_core_link_up gauge\ngateway_core_link_up 0.0\n"
        "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_breaker_metric_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # The breaker SAMPLE is absent (not latched → healthy), but the body is still the gateway's
    # own exposition — it declares a gateway_ family — so the identity check passes.
    _patch_fetch(monkeypatch, "# TYPE gateway_core_link_up gauge\ngateway_core_link_up 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_ignores_help_comment_line(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# HELP gateway_circuit_breaker_open 1 while latched\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_unhealthy_when_breaker_open(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open 1.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_unhealthy_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, None)
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_malformed_sample_is_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_circuit_breaker_open gauge\n"
        "gateway_circuit_breaker_open NaNgarbage extra\n",
    )
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code in (0, 1)
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_malformed_sample_treated_as_not_latched(monkeypatch: pytest.MonkeyPatch) -> None:
    # A garbled breaker value must parse as NOT latched (healthy), not silently unhealthy. The
    # body still declares a gateway_ family, so it passes the identity check and reaches the
    # breaker parse.
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open NaNgarbage\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_bad_port_env_is_unhealthy_not_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    # A malformed ALFRED_GATEWAY_METRICS_PORT must exit unhealthy, never raw-traceback.
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "notaport")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)


@pytest.mark.parametrize(
    "body",
    [
        "hello world\n",  # a squatter serving prose on the gateway metrics port
        "",  # an empty 200 body
        # the CORE's own exposition on a mis-set ALFRED_GATEWAY_METRICS_PORT (declares alfred_,
        # NOT gateway_) — the cross-service false-healthy this arm closes.
        "# HELP alfred_x x\n# TYPE alfred_x counter\nalfred_x 0.0\n",
    ],
)
def test_unhealthy_when_not_gateway_exposition(monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    """A 200 that is not the gateway's OWN exposition is unhealthy, not falsely healthy.

    Mirrors the daemon's #482/P4 identity arm: prose, an empty body, or the core's `alfred_`
    exposition on a mis-set port all used to read HEALTHY (a `gateway_` breaker sample was
    merely absent → not latched → healthy). The shared `declares_metric_family` predicate with
    the `gateway_` prefix closes that; the arm runs BEFORE the breaker check, so it fails on
    identity, not on the breaker parse.
    """
    _patch_fetch(monkeypatch, body)
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 1
    # Exit 1 is shared by the unreachable and breaker arms too — assert the identity arm's OWN
    # diagnostic actually rendered. Key on prose unique to this message ("own exposition"): it
    # distinguishes it from the other two arms AND proves `t()` resolved (the raw catalog key
    # `gateway.healthcheck.not_gateway_exposition` has no such phrase). A raw-key-absence check
    # would be vacuous here — structlog writes the event key to stdout regardless.
    assert "own exposition" in result.stdout


def test_real_gateway_registry_exposition_satisfies_the_identity_predicate() -> None:
    """Pin the identity check to the gateway's ACTUAL served exposition, not a stand-in.

    `healthcheck_gateway` requires a declared `gateway_` family; `alfred.gateway.metrics`
    registers those on the default registry at import, and `start_gateway` serves that default
    registry via `start_metrics_server(port)` (no explicit registry). If the gateway's metric
    names or their registration site ever drifted from the `gateway_` prefix, this fails LOUD
    instead of turning a live gateway permanently unhealthy. Oracle is independent of the
    predicate: exposition comes from prometheus_client's `generate_latest`.
    """
    from prometheus_client import generate_latest

    import alfred.gateway.metrics  # noqa: F401 — import registers gateway_* on the default registry
    from alfred.cli.gateway._commands import _GATEWAY_METRIC_FAMILY_PREFIX
    from alfred.observability.metrics_server import declares_metric_family

    exposition = generate_latest().decode()
    assert declares_metric_family(exposition, _GATEWAY_METRIC_FAMILY_PREFIX) is True


def test_start_honors_dial_adapter_id_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """`alfred gateway start` passes ALFRED_GATEWAY_DIAL_ADAPTER_ID into GatewayProcess
    so the gateway's core-dial target is operator-configurable (not a hidden constant)."""
    captured: dict[str, object] = {}

    class _FakeProcess:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def run(self) -> None:
            return None

    # start_gateway imports these LAZILY from their definition module, so patch
    # at the source — not on `_commands` — to exercise the real start body. That
    # source is `alfred.observability.metrics_server` (#470 promoted the exposition
    # there and DELETED the `alfred.gateway.metrics_server` shim); patching the old
    # path would silently no-op and let this test bind a real socket on 9464.
    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr(
        "alfred.observability.metrics_server.start_metrics_server", lambda port: True
    )
    monkeypatch.setattr(
        "alfred.observability.metrics_server.resolve_metrics_port", lambda *_a: 9464
    )
    monkeypatch.setenv("ALFRED_GATEWAY_DIAL_ADAPTER_ID", "alfred_tui")
    CliRunner().invoke(gateway_app, ["start"])
    assert captured.get("dial_adapter_id") == "alfred_tui"


def test_start_defaults_dial_adapter_id_to_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the env unset, start_gateway preserves the legacy `"tui"` dial target."""
    captured: dict[str, object] = {}

    class _FakeProcess:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def run(self) -> None:
            return None

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr(
        "alfred.observability.metrics_server.start_metrics_server", lambda port: True
    )
    monkeypatch.setattr(
        "alfred.observability.metrics_server.resolve_metrics_port", lambda *_a: 9464
    )
    monkeypatch.delenv("ALFRED_GATEWAY_DIAL_ADAPTER_ID", raising=False)
    CliRunner().invoke(gateway_app, ["start"])
    assert captured.get("dial_adapter_id") == "tui"


def test_start_coalesces_empty_dial_adapter_id_env_to_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    """An EMPTY ``ALFRED_GATEWAY_DIAL_ADAPTER_ID`` coalesces to the ``"tui"`` default.

    The start body resolves the dial target via ``os.environ.get(env) or _DEFAULT`` — so an
    env set to the empty string (an operator who exported the var with no value, or a shell
    that passes ``VAR=``) must fall through to the legacy ``"tui"`` default, NOT dial the
    empty-string adapter id (``default_comms_socket_path("")`` would itself raise on the
    adapter-id charset guard, a confusing failure mode). The ``or`` short-circuit is the
    intended semantics; this pins it so a future refactor to ``get(env, _DEFAULT)`` — which
    would pass the empty string through — is caught.
    """
    captured: dict[str, object] = {}

    class _FakeProcess:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def run(self) -> None:
            return None

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr(
        "alfred.observability.metrics_server.start_metrics_server", lambda port: True
    )
    monkeypatch.setattr(
        "alfred.observability.metrics_server.resolve_metrics_port", lambda *_a: 9464
    )
    monkeypatch.setenv("ALFRED_GATEWAY_DIAL_ADAPTER_ID", "")
    CliRunner().invoke(gateway_app, ["start"])
    assert captured.get("dial_adapter_id") == "tui"
