"""Unit tests for the shared Prometheus exposition module (#470).

Full line+branch coverage of ``alfred.observability.metrics_server`` is required now
(Task 3 of #470 PR1 adds a formal 100% gate on ``src/alfred/observability/`` — this
suite is written to already satisfy it): both ``start_metrics_server`` branches
(success + the loud-and-continue ``OSError`` path), both the default-registry and an
explicit-registry call shape, and the ``fetch_metrics_text`` happy path.
"""

from __future__ import annotations

import http.client

import pytest
import structlog.testing
from prometheus_client import CollectorRegistry

from alfred.observability.metrics_server import (
    fetch_metrics_text,
    resolve_metrics_port,
    start_metrics_server,
)

# ── resolve_metrics_port ──────────────────────────────────────────────────────


def test_resolve_uses_default_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_CORE_METRICS_PORT", raising=False)
    assert resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465) == 9465


def test_resolve_uses_default_when_env_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "")
    assert resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465) == 9465


def test_resolve_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9500")
    assert resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465) == 9500


def test_resolve_rejects_nonint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "notaport")
    with pytest.raises(ValueError):
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)


def test_resolve_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "70000")
    with pytest.raises(ValueError):
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "0")
    with pytest.raises(ValueError):
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)


# ── start_metrics_server ──────────────────────────────────────────────────────


def test_start_uses_default_registry_when_none_given(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, tuple[object, ...], dict[str, object]]] = []

    def _fake_start(port: int, *args: object, **kwargs: object) -> None:
        calls.append((port, args, kwargs))

    monkeypatch.setattr("alfred.observability.metrics_server.start_http_server", _fake_start)
    assert start_metrics_server(9465) is True
    assert calls == [(9465, (), {})]  # no registry kwarg threaded through


def test_start_passes_explicit_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = CollectorRegistry()
    calls: list[tuple[int, dict[str, object]]] = []

    def _fake_start(port: int, *, registry: object) -> None:
        calls.append((port, {"registry": registry}))

    monkeypatch.setattr("alfred.observability.metrics_server.start_http_server", _fake_start)
    assert start_metrics_server(9465, registry=registry) is True
    assert calls == [(9465, {"registry": registry})]


def test_start_loud_and_continue_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(port: int) -> None:
        raise OSError("address in use")

    monkeypatch.setattr("alfred.observability.metrics_server.start_http_server", _boom)
    with structlog.testing.capture_logs() as logs:
        assert start_metrics_server(9465) is False  # loud-and-continue, no raise
    assert any(e["event"] == "metrics.bind_failed" and e["port"] == 9465 for e in logs), (
        f"expected a metrics.bind_failed warning, got {logs!r}"
    )


# ── fetch_metrics_text ────────────────────────────────────────────────────────


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body


class _FakeConnection:
    """Stand-in for ``http.client.HTTPConnection`` — records the request, returns fixture bytes."""

    last_request: tuple[str, str] | None = None
    closed: bool = False

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method: str, path: str) -> None:
        _FakeConnection.last_request = (method, path)

    def getresponse(self) -> _FakeResponse:
        return _FakeResponse(b"gateway_egress_inflight 1.0\n")

    def close(self) -> None:
        _FakeConnection.closed = True


def test_fetch_metrics_text_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http.client, "HTTPConnection", _FakeConnection)
    text = fetch_metrics_text("127.0.0.1", 9465)
    assert text == "gateway_egress_inflight 1.0\n"
    assert _FakeConnection.last_request == ("GET", "/metrics")
    assert _FakeConnection.closed is True
