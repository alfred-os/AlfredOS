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


# ── Line 74: _denied_by_plane skips non-_total companion samples ──────────────


def test_created_companion_sample_is_skipped() -> None:
    """Line 74: _denied_by_plane silently skips any sample whose name != _total.

    Prometheus counters emit a ``_created`` companion sample alongside the ``_total``
    sample.  The skip ensures the companion does not corrupt the reason-count map.
    """
    from prometheus_client.metrics_core import Metric, Sample

    family = Metric("gateway_egress_denied", "", "counter")
    family.samples = [
        Sample(
            "gateway_egress_denied_total",
            {"plane": "proxy", "reason": "literal_ip_target"},
            1.0,
            None,
            None,
        ),
        Sample(
            "gateway_egress_denied_created",
            {"plane": "proxy", "reason": "literal_ip_target"},
            1_751_234_567.0,  # Unix epoch seconds — a realistic _created value
            None,
            None,
        ),
    ]
    result = _egress._denied_by_plane(family)
    # Only the _total sample contributes; the _created companion is skipped.
    assert result == {"proxy": {"literal_ip_target": 1.0}}


# ── Lines 130-132: relay branch of _reason_description ───────────────────────

_METRICS_WITH_RELAY_DENIAL = """\
# TYPE gateway_egress_inflight gauge
gateway_egress_inflight{plane="proxy"} 0.0
gateway_egress_inflight{plane="relay"} 1.0
# TYPE gateway_egress_denied_total counter
gateway_egress_denied_total{plane="relay",reason="destination_not_allowlisted"} 2.0
# TYPE gateway_adapter_up gauge
gateway_adapter_up{adapter="discord"} 1.0
"""


def test_relay_deny_reason_is_rendered(capsys, monkeypatch) -> None:
    """Lines 130, 132: relay plane with a valid deny reason renders via relay_reason_key."""
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS_WITH_RELAY_DENIAL)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    # Both the reason token and its count must appear in the relay stanza.
    assert "destination_not_allowlisted=2" in out


def test_unknown_relay_reason_fails_loud(monkeypatch) -> None:
    """Lines 130, 131: an invalid relay reason token raises ValueError (hard rule #7)."""
    bad_relay_metrics = _METRICS_WITH_RELAY_DENIAL.replace(
        "destination_not_allowlisted", "totally_bogus_relay_reason"
    )
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: bad_relay_metrics)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    with pytest.raises(ValueError, match="unknown egress deny reason"):
        _egress.egress_status()


# ── Lines 169-171, 188-190, 209-211: _render_allowlists degrade branches ─────


def test_proxy_allowlist_degrade_renders_unresolved(capsys, monkeypatch) -> None:
    """Lines 169-171: provider allowlist derivation failure degrades to 'unresolved'."""
    import alfred.gateway.egress_proxy as _egress_proxy_mod

    def _boom() -> str:
        raise RuntimeError("simulated proxy allowlist failure")

    monkeypatch.setattr(_egress_proxy_mod, "resolve_deepseek_base_url", _boom)
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "proxy: (unresolved" in out


def test_relay_allowlist_degrade_renders_unresolved(capsys, monkeypatch) -> None:
    """Lines 188-190: relay allowlist derivation failure degrades to 'unresolved'."""
    import alfred.gateway.egress_relay as _egress_relay_mod

    def _boom() -> frozenset:  # type: ignore[type-arg]
        raise RuntimeError("simulated relay allowlist failure")

    monkeypatch.setattr(_egress_relay_mod, "resolve_tool_egress_allowlist", _boom)
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "relay: (unresolved" in out


def test_discord_allowlist_degrade_renders_unresolved(capsys, monkeypatch) -> None:
    """Lines 209-211: discord allowlist derivation failure degrades to 'unresolved'."""
    import alfred.egress.allowlist as _allowlist_mod

    def _boom(*a: object, **kw: object) -> None:
        raise RuntimeError("simulated discord allowlist failure")

    monkeypatch.setattr(_allowlist_mod, "discord_egress_allowlist", _boom)
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "adapter(discord): (unresolved" in out
