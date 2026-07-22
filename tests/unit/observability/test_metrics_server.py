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

from alfred.observability import metrics_server as metrics_server_module
from alfred.observability.metrics_server import (
    CORE_METRIC_FAMILY_PREFIX,
    CORE_METRICS_DEFAULT_PORT,
    CORE_METRICS_PORT_ENV,
    declares_metric_family,
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


@pytest.mark.parametrize("bad", ["notaport", "70000"])
def test_resolve_refusal_names_env_range_and_value(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """dx-001: BOTH refusal arms must be actionable on their own.

    ``alfred daemon healthcheck`` quotes this text verbatim to the operator, so the
    non-integer arm (which used to surface a bare ``int()`` message naming neither the
    variable nor the range) has to carry the same three facts as the range arm: which env
    var, what is accepted, and what the operator actually set.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", bad)
    with pytest.raises(ValueError) as exc_info:
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)
    message = str(exc_info.value)
    assert "ALFRED_CORE_METRICS_PORT" in message
    assert "1..65535" in message
    assert bad in message


def test_core_port_pair_is_the_single_source_of_truth(monkeypatch: pytest.MonkeyPatch) -> None:
    """rev-001 / sec-003: the (env var, default) pair the boot seam binds and the healthcheck
    probes is ONE constant pair, exported here and imported by both.

    A drift between them would leave the exposition on one port and the probe on another —
    the healthcheck would go permanently red, killing the only mechanism that surfaces a
    metrics bind failure. The DEFAULT is exercised explicitly (env deleted, not set) because
    every other consumer test pins the port via the env and so never proves the fallback.
    """
    assert CORE_METRICS_PORT_ENV == "ALFRED_CORE_METRICS_PORT"
    monkeypatch.delenv(CORE_METRICS_PORT_ENV, raising=False)
    assert resolve_metrics_port(CORE_METRICS_PORT_ENV, CORE_METRICS_DEFAULT_PORT) == 9465


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
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]


class _FakeConnection:
    """Stand-in for ``http.client.HTTPConnection`` — records the request, returns fixture bytes."""

    body: bytes = b"gateway_egress_inflight 1.0\n"
    status: int = 200

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.last_request: tuple[str, str] | None = None
        self.closed: bool = False

    def request(self, method: str, path: str) -> None:
        self.last_request = (method, path)

    def getresponse(self) -> _FakeResponse:
        return _FakeResponse(self.body, self.status)

    def close(self) -> None:
        self.closed = True


def _install_fake_conn(
    monkeypatch: pytest.MonkeyPatch, *, body: bytes | None = None, status: int = 200
) -> list[_FakeConnection]:
    """Patch ``http.client.HTTPConnection`` with a recording fake; return the created list."""
    created: list[_FakeConnection] = []

    def _factory(host: str, port: int, timeout: float | None = None) -> _FakeConnection:
        conn = _FakeConnection(host, port, timeout)
        if body is not None:
            conn.body = body
        conn.status = status
        created.append(conn)
        return conn

    monkeypatch.setattr(http.client, "HTTPConnection", _factory)
    return created


def test_fetch_metrics_text_success(monkeypatch: pytest.MonkeyPatch) -> None:
    created = _install_fake_conn(monkeypatch)
    text = fetch_metrics_text(9465)
    assert text == "gateway_egress_inflight 1.0\n"
    assert len(created) == 1
    assert created[0].last_request == ("GET", "/metrics")
    assert created[0].closed is True


def test_fetch_metrics_text_always_dials_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec-001: the destination host is structural, not a caller-supplied parameter.

    The signature is the guarantee — ``fetch_metrics_text`` takes a port and nothing else, so
    no call site (in a module the connectivity-free core imports at boot, and which the
    in-core HTTP-egress AST ratchet exempts because it uses ``http.client``) can express a
    non-loopback destination. This pins BOTH halves: the dialled host, and the fact that
    passing a host is a ``TypeError`` rather than a silently-honoured redirection.
    """
    created = _install_fake_conn(monkeypatch)
    fetch_metrics_text(9465)
    assert created[0].host == "127.0.0.1"
    with pytest.raises(TypeError):
        fetch_metrics_text("evil.example.com", 9465)  # type: ignore[arg-type, call-arg]


@pytest.mark.parametrize("status", [404, 500, 301, 204])
def test_fetch_metrics_text_non_200_is_an_oserror(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """CR-A: a non-200 body is NOT an exposition.

    Before this check the healthcheck read a 404 (wrong path / a non-metrics HTTP server
    squatting on the port) or a 500 (wedged handler) as HEALTHY — i.e. it could not fail for
    the very case it exists to catch. The refusal must be an ``OSError`` so each consumer's
    single ``except OSError`` still covers it, and the connection must still be closed.
    """
    created = _install_fake_conn(monkeypatch, body=b"<html>not metrics</html>", status=status)
    with pytest.raises(OSError, match=f"HTTP {status}"):
        fetch_metrics_text(9465)
    assert created[0].closed is True


def test_fetch_metrics_text_rejects_oversized_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec-005: an unbounded ``.read()`` lets whatever answers stream the probe out of memory.

    Over-cap fails LOUD (an ``OSError``, like every other fetch failure) rather than silently
    truncating into a half-parsed exposition, which would read as a plausible-but-wrong scrape.
    """
    oversize = b"x" * (metrics_server_module._MAX_METRICS_BYTES + 1)
    created = _install_fake_conn(monkeypatch, body=oversize)
    with pytest.raises(OSError, match="exceeded"):
        fetch_metrics_text(9465)
    assert created[0].closed is True


def test_fetch_metrics_text_accepts_body_exactly_at_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The boundary is inclusive: a body of exactly the cap is served, not refused."""
    at_cap = b"a" * metrics_server_module._MAX_METRICS_BYTES
    _install_fake_conn(monkeypatch, body=at_cap)
    assert fetch_metrics_text(9465) == at_cap.decode()


class _FakeConnectionBadStatusLine:
    """A responder on the metrics port that isn't speaking HTTP at all.

    ``getresponse`` raises ``http.client.HTTPException`` (e.g. a real ``BadStatusLine``) —
    NOT an ``OSError`` subclass — so this exercises the re-raise-as-``OSError`` branch that
    keeps every ``fetch_metrics_text`` consumer's single ``except OSError`` catch surface
    honest (#470 final-review required fix).
    """

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.closed = False

    def request(self, method: str, path: str) -> None:
        pass

    def getresponse(self) -> _FakeResponse:
        raise http.client.BadStatusLine("not an HTTP response")

    def close(self) -> None:
        self.closed = True


def test_fetch_metrics_text_reraises_http_exception_as_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[_FakeConnectionBadStatusLine] = []

    def _factory(
        host: str, port: int, timeout: float | None = None
    ) -> _FakeConnectionBadStatusLine:
        conn = _FakeConnectionBadStatusLine(host, port, timeout)
        created.append(conn)
        return conn

    monkeypatch.setattr(http.client, "HTTPConnection", _factory)
    with pytest.raises(OSError) as exc_info:
        fetch_metrics_text(9465)
    assert isinstance(exc_info.value.__cause__, http.client.HTTPException)
    assert len(created) == 1
    assert created[0].closed is True  # the `finally` still closes the connection


# ── declares_metric_family (#482 P4 — the /metrics identity predicate) ─────────


@pytest.mark.parametrize(
    "exposition",
    [
        "# HELP alfred_x help\n# TYPE alfred_x counter\nalfred_x 0.0\n",
        "# TYPE alfred_x counter\nalfred_x 0.0\n",  # # TYPE alone is sufficient
        "# HELP alfred_x help\n",  # # HELP alone is sufficient
        "# HELP   alfred_x help\n",  # tolerant of extra whitespace after the declaration
        "some preamble\n# TYPE alfred_y gauge\nalfred_y 1\n",  # not required to be the first line
    ],
)
def test_declares_metric_family_accepts_a_declared_alfred_family(exposition: str) -> None:
    assert declares_metric_family(exposition, CORE_METRIC_FAMILY_PREFIX) is True


@pytest.mark.parametrize(
    "exposition",
    [
        "",  # empty body (uat-p4)
        "hello world\n",  # prose 200 (uat-p4)
        # the GATEWAY's exposition on a mis-set port (uat-p4)
        "# HELP gateway_up 1\n# TYPE gateway_up gauge\ngateway_up 1\n",
        "alfred_x 0.0\n",  # a bare sample line with no HELP/TYPE declaration does not count
        "#HELP alfred_x help\n",  # a malformed declaration (no space) is not a declaration
        "# HELP notalfred_x help\n",  # a family that only contains, not starts with, the prefix
    ],
)
def test_declares_metric_family_rejects_a_non_core_exposition(exposition: str) -> None:
    assert declares_metric_family(exposition, CORE_METRIC_FAMILY_PREFIX) is False


def test_real_curated_registry_exposition_satisfies_the_predicate() -> None:
    """Pin the predicate to the ACTUAL core exposition, not a hand-written stand-in.

    The docstring promises the prefix constant and ``declares_metric_family`` are "pinned
    together by a test that asserts the REAL curated registry's exposition satisfies the
    predicate". Without this, the constant could drift from what the curated registry actually
    emits and the probe would call a live core UNHEALTHY. Derived independently of the
    predicate (via ``generate_latest``), so it is not a tautological oracle.
    """
    from prometheus_client import generate_latest

    from alfred.observability.core_metrics import build_core_registry

    exposition = generate_latest(build_core_registry()).decode()
    assert declares_metric_family(exposition, CORE_METRIC_FAMILY_PREFIX) is True
