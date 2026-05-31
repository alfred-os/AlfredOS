"""Behavioural tests: dispatch + spawn paths observe the spec §7a.1 histograms.

The shape tests in ``test_transport_perf_budgets.py`` pin the histogram
*surface* (names, labels, buckets). The tests here pin the *behaviour*:
every dispatch exit path lands an observation with the correct
``outcome`` label, and the spawn path lands a ``spawn_failed`` observation
when ``create_subprocess_exec`` raises.

Why this matters: a refactor that re-orders the ``try/finally`` or drops
a label silently breaks the dashboards without breaking the surface
tests. The behavioural assertions catch those regressions before they
hit production observability.

The tests use the default ``CollectorRegistry`` (which the module-level
histograms register against at import time). To make assertions
independent of execution order, we sample each labelled child's
``_sum`` and ``_count`` immediately before and after the dispatch call
and assert the delta — never the absolute value.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.plugins._observability import (
    DISPATCH_DURATION,
    INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION,
    PLUGIN_SPAWN_DURATION,
)
from alfred.plugins.errors import DlpOutboundRefusedError
from alfred.plugins.stdio_transport import (
    CanaryTripSecurityEvent,
    StdioTransport,
)


def _child_count(hist: Any, **labels: str) -> float:
    """Return the labelled child's current ``_count`` sample value.

    Reads via the public ``collect()`` API so this stays stable across
    prometheus_client internal refactors.
    """
    # Pre-create the child so it appears in collect() before any observe.
    hist.labels(**labels)
    for fam in hist.collect():
        for sample in fam.samples:
            if sample.name.endswith("_count") and sample.labels == labels:
                return float(sample.value)
    return 0.0


def _child_sum(hist: Any, **labels: str) -> float:
    """Return the labelled child's current ``_sum`` sample value."""
    hist.labels(**labels)
    for fam in hist.collect():
        for sample in fam.samples:
            if sample.name.endswith("_sum") and sample.labels == labels:
                return float(sample.value)
    return 0.0


@pytest.fixture
def make_transport(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> Any:
    """Factory returning a transport with custom DLP + scanner behaviour."""

    def _make(
        *,
        dlp: MagicMock | None = None,
        scanner: MagicMock | None = None,
        plugin_id: str = "test.plugin.histogram",
    ) -> StdioTransport:
        if dlp is None:
            dlp = MagicMock()
            dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
        if scanner is None:
            scanner = MagicMock()
            scanner.scan.return_value = None
        return StdioTransport(
            plugin_id=plugin_id,
            executable="/bin/sh",
            args=["-c", "true"],
            audit_writer=fake_audit_writer,
            dlp=dlp,
            scanner=scanner,
            secret_broker=fake_broker,
            inbound_t3_nonce=stub_nonce,
        )

    return _make


@pytest.mark.asyncio
async def test_dispatch_dlp_refused_observes_dlp_refused_outcome(
    make_transport: Any,
) -> None:
    """A DLP-refused dispatch observes ``DISPATCH_DURATION`` with outcome=dlp_refused."""
    refusing_dlp = MagicMock()
    refusing_dlp.scan.return_value = MagicMock(refused=True, rule_matched="api_key")
    transport = make_transport(dlp=refusing_dlp, plugin_id="test.dlp_refused")

    before = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.dlp_refused",
        method_shape="content",
        outcome="dlp_refused",
    )
    dlp_before = _child_count(OUTBOUND_DLP_SCAN_DURATION, outcome="refused")
    with pytest.raises(DlpOutboundRefusedError):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    after = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.dlp_refused",
        method_shape="content",
        outcome="dlp_refused",
    )
    dlp_after = _child_count(OUTBOUND_DLP_SCAN_DURATION, outcome="refused")
    assert after - before == 1.0
    assert dlp_after - dlp_before == 1.0


@pytest.mark.asyncio
async def test_dispatch_called_before_spawn_observes_error_outcome(
    make_transport: Any,
) -> None:
    """A dispatch on a transport that never spawned observes outcome=error."""
    transport = make_transport(plugin_id="test.never_spawned")

    before = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.never_spawned",
        method_shape="content",
        outcome="error",
    )
    with pytest.raises(RuntimeError, match="called before _spawn"):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    after = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.never_spawned",
        method_shape="content",
        outcome="error",
    )
    assert after - before == 1.0


@pytest.mark.asyncio
async def test_dispatch_canary_trip_observes_canary_trip_outcome(
    make_transport: Any,
) -> None:
    """A canary trip observes outcome=canary_trip on DISPATCH + canary_trip on INBOUND."""
    from alfred.plugins.inbound_scanner import CanaryTrip

    scanner = MagicMock()
    scanner.scan.return_value = CanaryTrip(
        matched_token="alfred-canary",  # noqa: S106 -- canary marker, not a secret
        frame_offset=0,
    )
    transport = make_transport(scanner=scanner, plugin_id="test.canary_trip")

    # Simulate a spawned subprocess: stub _process + _read_length_prefixed
    transport._process = MagicMock()
    transport._process.stdin = MagicMock()
    transport._process.stdin.drain = AsyncMock()
    transport._read_length_prefixed = AsyncMock(return_value=b'{"result": "x"}')

    dispatch_before = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.canary_trip",
        method_shape="content",
        outcome="canary_trip",
    )
    scan_before = _child_count(INBOUND_SCANNER_SCAN_DURATION, outcome="canary_trip")
    with pytest.raises(CanaryTripSecurityEvent):
        await transport.dispatch("web.fetch", {"url": "https://x"})
    dispatch_after = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.canary_trip",
        method_shape="content",
        outcome="canary_trip",
    )
    scan_after = _child_count(INBOUND_SCANNER_SCAN_DURATION, outcome="canary_trip")
    assert dispatch_after - dispatch_before == 1.0
    assert scan_after - scan_before == 1.0


@pytest.mark.asyncio
async def test_dispatch_unexpected_exception_observes_error_outcome(
    make_transport: Any,
) -> None:
    """An unrelated exception observed mid-dispatch lands outcome=error and re-raises."""
    boom_broker = MagicMock()
    boom_broker.substitute = AsyncMock(side_effect=ValueError("broker exploded"))
    transport = StdioTransport(
        plugin_id="test.broker_boom",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=MagicMock(append_schema=AsyncMock()),
        dlp=MagicMock(scan=MagicMock(return_value=MagicMock(refused=False, rule_matched=None))),
        scanner=MagicMock(scan=MagicMock(return_value=None)),
        secret_broker=boom_broker,
        inbound_t3_nonce=MagicMock(),
    )

    before = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.broker_boom",
        method_shape="content",
        outcome="error",
    )
    with pytest.raises(ValueError, match="broker exploded"):
        await transport.dispatch("web.fetch", {"url": "https://x"})
    after = _child_count(
        DISPATCH_DURATION,
        plugin_id="test.broker_boom",
        method_shape="content",
        outcome="error",
    )
    assert after - before == 1.0


@pytest.mark.asyncio
async def test_spawn_missing_executable_observes_spawn_failed(
    make_transport: Any,
) -> None:
    """``_spawn`` of a non-existent executable observes ``spawn_failed``."""
    transport = StdioTransport(
        plugin_id="test.spawn_fail",
        executable="/nonexistent/path/to/binary",
        args=[],
        audit_writer=MagicMock(),
        dlp=MagicMock(),
        scanner=MagicMock(),
        secret_broker=MagicMock(),
        inbound_t3_nonce=MagicMock(),
    )

    before = _child_count(
        PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_fail", outcome="spawn_failed"
    )
    with pytest.raises(FileNotFoundError):
        await transport._spawn()
    after = _child_count(PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_fail", outcome="spawn_failed")
    assert after - before == 1.0


@pytest.mark.asyncio
async def test_spawn_success_observes_ok(make_transport: Any) -> None:
    """``_spawn`` of a real executable observes ``ok`` and the spawn duration is recorded."""
    transport = StdioTransport(
        plugin_id="test.spawn_ok",
        executable="/bin/sh",
        args=["-c", "exec cat"],
        audit_writer=MagicMock(),
        dlp=MagicMock(),
        scanner=MagicMock(),
        secret_broker=MagicMock(),
        inbound_t3_nonce=MagicMock(),
    )

    before = _child_count(PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_ok", outcome="ok")
    sum_before = _child_sum(PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_ok", outcome="ok")
    try:
        await transport._spawn()
        after = _child_count(PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_ok", outcome="ok")
        sum_after = _child_sum(PLUGIN_SPAWN_DURATION, plugin_id="test.spawn_ok", outcome="ok")
        assert after - before == 1.0
        # Sum strictly increases (any non-zero duration) — exact value
        # depends on host load, so the property is "> 0" not equality.
        assert sum_after > sum_before
    finally:
        await transport.close()
