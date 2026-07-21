"""``alfred gateway egress`` — operator egress-plane state (Spec C G7-5 PR-A).

Runs IN the gateway container. Scrapes the loopback ``/metrics`` (the seam
``healthcheck`` uses) and reads the static allowlist config; renders per-plane
stanzas. Exit 0 on success, 2 when ``/metrics`` is unavailable (report-family
semantics, never a traceback — hard rule #7).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Final

import structlog
import typer
from prometheus_client.metrics_core import Metric
from prometheus_client.parser import text_string_to_metric_families

from alfred.cli.gateway._commands import (
    _GATEWAY_METRICS_DEFAULT_PORT,
    _GATEWAY_METRICS_PORT_ENV,
    _HEALTHCHECK_HOST,
)
from alfred.egress.relay_protocol import EgressRelayDenyReason
from alfred.gateway.egress_audit import EgressDenyReason
from alfred.gateway.metrics_server import resolve_metrics_port
from alfred.i18n import t
from alfred.observability.metrics_server import fetch_metrics_text

log = structlog.get_logger(__name__)

_EXIT_UNAVAILABLE: Final[int] = 2

# Per-plane closed reason enums used for token validation in _validate_reason.
_PROXY_REASONS: Final = {r.value for r in EgressDenyReason}
_RELAY_REASONS: Final = {r.value for r in EgressRelayDenyReason}


def egress_status() -> None:
    """Render the per-plane egress state; raise ``typer.Exit(2)`` on metrics unavailable."""
    port: int | str = "unset"
    try:
        port = resolve_metrics_port(_GATEWAY_METRICS_PORT_ENV, _GATEWAY_METRICS_DEFAULT_PORT)
        metrics_text = fetch_metrics_text(_HEALTHCHECK_HOST, port)
        # Parse INSIDE the try: a malformed /metrics exposition raises ValueError, which
        # must exit 2 ("never a traceback", hard rule #7 / the module docstring), NOT
        # escape. Reason-drift ValueErrors from _render_* below stay fail-loud (those are
        # a deploy-skew invariant violation, not a backend-unavailable condition).
        families = {f.name: f for f in text_string_to_metric_families(metrics_text)}
    except (OSError, ValueError) as exc:
        log.warning("gateway.egress.unreachable", port=port, error=repr(exc))
        typer.echo(t("gateway.egress.unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc
    inflight = _samples_by_label(families.get("gateway_egress_inflight"), "plane")
    # The counter FAMILY name is ``_total``-stripped by the prometheus parser; the
    # presence of the family (vs a plane's zero count) is tracked so "no denials" ≠
    # "metric absent" (brief §8(a) — two DISTINCT output paths).
    denied_family_present = "gateway_egress_denied" in families
    denied = _denied_by_plane(families.get("gateway_egress_denied"))
    adapter_up = _samples_by_label(families.get("gateway_adapter_up"), "adapter")

    _render_plane("proxy", "gateway.egress.plane.proxy", inflight, denied, denied_family_present)
    _render_plane("relay", "gateway.egress.plane.relay", inflight, denied, denied_family_present)
    _render_adapter(inflight, denied, denied_family_present, adapter_up=adapter_up)

    # Per-plane static allowlist (config read, not a scrape).
    _render_allowlists()


def _samples_by_label(family: Metric | None, label: str) -> dict[str, float]:
    if family is None:
        return {}
    return {s.labels[label]: s.value for s in family.samples if label in s.labels}


def _denied_by_plane(family: Metric | None) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    if family is None:
        return out
    for s in family.samples:
        if s.name != "gateway_egress_denied_total":
            continue
        out.setdefault(s.labels["plane"], {})[s.labels["reason"]] = s.value
    return out


def _render_plane(
    plane: str,
    header_key: str,
    inflight: dict[str, float],
    denied: dict[str, dict[str, float]],
    denied_family_present: bool,
) -> None:
    # Reached only PAST the exit-2 /metrics check, so proxy/relay are up (fail-closed
    # bind — a down proxy/relay means the gateway already exited). Hence no "down" branch.
    typer.echo(t(header_key) + "  " + t("gateway.egress.reachable"))
    typer.echo("  " + t("gateway.egress.inflight_label") + " " + str(int(inflight.get(plane, 0))))
    typer.echo(
        "  "
        + t("gateway.egress.denies_label")
        + " "
        + _fmt_denies(plane, denied.get(plane, {}), denied_family_present)
    )


def _fmt_denies(plane: str, reasons: dict[str, float], family_present: bool) -> str:
    """Format the deny-reason breakdown for one plane.

    Two DISTINCT paths (brief §8(a)):
    * family absent entirely → ``denies_unavailable`` (metric not yet wired);
    * family present, plane has no nonzero count → ``no_denials``.
    """
    if not family_present:  # deny counter not exposed — distinct from "0 denies"
        return t("gateway.egress.denies_unavailable")
    nonzero = {r: int(v) for r, v in reasons.items() if v > 0}
    if not nonzero:
        return t("gateway.egress.no_denials")
    parts: list[str] = []
    for reason, count in sorted(nonzero.items()):
        # Validate against the plane's closed enum. Metric label VALUES stay English
        # (reason token = Prometheus-correlatable) — no verbose description inline.
        _validate_reason(plane, reason)
        parts.append(f"{reason}={count}")
    return "  ".join(parts)


def _validate_reason(plane: str, reason: str) -> None:
    """Validate ``reason`` against the plane's closed enum.

    Raises ``ValueError`` on an unknown reason token so metric drift fails loud
    (display-side payload-blindness — hard rule #7).
    """
    if plane in {"proxy", "adapter"}:
        if reason not in _PROXY_REASONS:
            raise ValueError(f"unknown egress deny reason {reason!r} for plane {plane!r}")
        return
    if reason not in _RELAY_REASONS:
        raise ValueError(f"unknown egress deny reason {reason!r} for plane {plane!r}")


def _render_adapter(
    inflight: dict[str, float],
    denied: dict[str, dict[str, float]],
    denied_family_present: bool,
    *,
    adapter_up: dict[str, float],
) -> None:
    if not adapter_up:
        typer.echo(t("gateway.egress.plane.adapter") + "  " + t("gateway.egress.not_configured"))
        return
    if not any(v >= 1.0 for v in adapter_up.values()):
        # Series present but value < 1.0 → adapter is configured but not currently serving
        # (crashed / breaker-open / spawning).
        typer.echo(t("gateway.egress.plane.adapter") + "  " + t("gateway.egress.adapter_down"))
        return
    _render_plane(
        "adapter", "gateway.egress.plane.adapter", inflight, denied, denied_family_present
    )


def _emit_allowlist_line(
    plane_header_key: str,
    plane_suffix: str,
    build_entries: Callable[[], list[str]],
) -> None:
    """Emit one allowlist summary line; degrades loudly on error (never crashes the report)."""
    label = t("gateway.egress.allowlist_label")
    plane_name = t(plane_header_key) + plane_suffix
    try:
        entries = build_entries()
        typer.echo(
            label
            + " "
            + plane_name
            + ": "
            + (", ".join(entries) if entries else t("gateway.egress.allowlist_empty"))
        )
    except Exception as exc:  # degrade loudly — never crash the report
        log.warning("gateway.egress.allowlist_unresolved", plane=plane_header_key, error=repr(exc))
        typer.echo(label + " " + plane_name + ": " + t("gateway.egress.allowlist_unresolved"))


def _render_allowlists() -> None:
    """Print a per-plane allowlist summary line (config read, not a scrape).

    Each plane's allowlist is derived from live env/config — the same derivation the
    gateway uses at boot — so the printed set cannot drift from what the proxy/relay
    actually enforces.
    """

    def _proxy_entries() -> list[str]:
        from alfred.egress.allowlist import provider_egress_allowlist
        from alfred.gateway.egress_proxy import resolve_deepseek_base_url

        return sorted(f"{h}:{p}" for h, p in provider_egress_allowlist(resolve_deepseek_base_url()))

    def _relay_entries() -> list[str]:
        from alfred.gateway.egress_relay import resolve_tool_egress_allowlist

        return sorted(f"{h}:{p}" for h, p in resolve_tool_egress_allowlist())

    def _discord_entries() -> list[str]:
        from alfred.egress.allowlist import discord_egress_allowlist

        # Thread the operator-added env var exactly as _commands.py:352 does so the
        # report cannot drift from what the adapter proxy actually enforces.
        al = discord_egress_allowlist(os.environ.get("ALFRED_DISCORD_EGRESS_ALLOWLIST", ""))
        exact = sorted(f"{h}:{p}" for h, p in al.exact)
        suffix = sorted(f"*.{h}:{p}" for h, p in al.suffix_bases)
        return exact + suffix

    _emit_allowlist_line("gateway.egress.plane.proxy", "", _proxy_entries)
    _emit_allowlist_line("gateway.egress.plane.relay", "", _relay_entries)
    _emit_allowlist_line("gateway.egress.plane.adapter", "(discord)", _discord_entries)


__all__ = ["egress_status"]
