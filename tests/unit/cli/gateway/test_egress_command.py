"""Unit tests for `alfred gateway egress` (render from a fixture /metrics blob)."""

from __future__ import annotations

import pytest
import typer

from alfred.cli.gateway import _egress

_METRICS = """\
# TYPE gateway_egress_inflight gauge
gateway_egress_inflight{plane="proxy"} 2.0
gateway_egress_inflight{plane="relay"} 0.0
# TYPE gateway_egress_denied_total counter
gateway_egress_denied_total{plane="proxy",reason="literal_ip_target"} 1.0
# TYPE gateway_adapter_up gauge
gateway_adapter_up{adapter="discord"} 1.0
"""


def test_happy_path_renders_all_planes(capsys, monkeypatch) -> None:
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "2" in out  # proxy inflight
    assert "literal_ip_target" in out or "gateway.egress.denied.literal_ip_target" in out


def test_metrics_unreachable_exits_2(monkeypatch) -> None:
    def _boom(_p: int) -> str:
        raise OSError("connection refused")

    monkeypatch.setattr(_egress, "_fetch_metrics_text", _boom)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    with pytest.raises(typer.Exit) as exc:
        _egress.egress_status()
    assert exc.value.exit_code == 2


def test_no_adapter_up_series_reports_not_configured(capsys, monkeypatch) -> None:
    metrics_no_adapter = _METRICS.replace(
        '# TYPE gateway_adapter_up gauge\ngateway_adapter_up{adapter="discord"} 1.0\n', ""
    )
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: metrics_no_adapter)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    # Adapter stanza must render the gateway.egress.not_configured msgstr.
    assert "not configured (no adapter up)" in out


def test_unknown_reason_token_fails_loud(monkeypatch) -> None:
    bad = _METRICS.replace("literal_ip_target", "totally_bogus_reason")
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: bad)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    with pytest.raises((ValueError, typer.Exit)):
        _egress.egress_status()


def test_zero_count_plane_shows_no_denials(capsys, monkeypatch) -> None:
    # M2: the deny family IS present but has no nonzero sample for the relay plane.
    # Expected: relay stanza shows the gateway.egress.no_denials msgstr, NOT
    # gateway.egress.denies_unavailable (which is reserved for the family-absent path).
    metrics_family_present_no_relay_denial = """\
# TYPE gateway_egress_inflight gauge
gateway_egress_inflight{plane="proxy"} 1.0
gateway_egress_inflight{plane="relay"} 0.0
# TYPE gateway_egress_denied_total counter
gateway_egress_denied_total{plane="proxy",reason="literal_ip_target"} 1.0
# TYPE gateway_adapter_up gauge
gateway_adapter_up{adapter="discord"} 1.0
"""
    monkeypatch.setattr(
        _egress, "_fetch_metrics_text", lambda _p: metrics_family_present_no_relay_denial
    )
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "no denials" in out
    assert "deny counter unavailable" not in out


def test_present_zero_vs_metric_absent_are_distinct(capsys, monkeypatch) -> None:
    # design §8(a): a present deny family with no nonzero count for a plane → "no denials";
    # the family ABSENT entirely → a DISTINCT "unavailable" output (metric not wired).
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    _egress.egress_status()
    with_family = capsys.readouterr().out
    no_family = _METRICS.replace(
        "# TYPE gateway_egress_denied_total counter\n"
        'gateway_egress_denied_total{plane="proxy",reason="literal_ip_target"} 1.0\n',
        "",
    )
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: no_family)
    _egress.egress_status()
    without_family = capsys.readouterr().out
    assert with_family != without_family  # "no denials"/counts vs "deny counter unavailable"
