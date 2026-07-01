"""``alfred gateway egress`` — operator egress-plane state (Spec C G7-5 PR-A).

Runs IN the gateway container. Scrapes the loopback ``/metrics`` (the seam
``healthcheck`` uses) and reads the static allowlist config; renders per-plane
stanzas. Exit 0 on success, 2 when ``/metrics`` is unavailable (report-family
semantics, never a traceback — hard rule #7).
"""

from __future__ import annotations

from typing import Final

import structlog
import typer
from prometheus_client.metrics_core import Metric
from prometheus_client.parser import text_string_to_metric_families

from alfred.cli.gateway._commands import _fetch_metrics_text
from alfred.egress.relay_protocol import EgressRelayDenyReason
from alfred.gateway.egress_audit import EgressDenyReason
from alfred.gateway.egress_audit import reason_i18n_key as proxy_reason_key
from alfred.gateway.egress_relay_audit import reason_i18n_key as relay_reason_key
from alfred.gateway.metrics_server import resolve_metrics_port
from alfred.i18n import t

log = structlog.get_logger(__name__)

_EXIT_UNAVAILABLE: Final[int] = 2

# Per-plane closed reason enums + their i18n key functions.
_PROXY_REASONS: Final = {r.value for r in EgressDenyReason}
_RELAY_REASONS: Final = {r.value for r in EgressRelayDenyReason}


def egress_status() -> None:
    """Render the per-plane egress state; raise ``typer.Exit(2)`` on metrics unavailable."""
    try:
        port = resolve_metrics_port()
        metrics_text = _fetch_metrics_text(port)
    except (OSError, ValueError) as exc:
        log.warning("gateway.egress.unreachable", error=repr(exc))
        typer.echo(t("gateway.egress.unreachable"))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc

    families = {f.name: f for f in text_string_to_metric_families(metrics_text)}
    inflight = _samples_by_label(families.get("gateway_egress_inflight"), "plane")
    # The counter FAMILY name is ``_total``-stripped by the prometheus parser; the
    # presence of the family (vs a plane's zero count) is tracked so "no denials" ≠
    # "metric absent" (brief §8(a) — two DISTINCT output paths).
    denied_family_present = "gateway_egress_denied" in families
    denied = _denied_by_plane(families.get("gateway_egress_denied"))
    adapter_up = _samples_by_label(families.get("gateway_adapter_up"), "adapter")

    _render_plane("proxy", "gateway.egress.plane.proxy", inflight, denied, denied_family_present)
    _render_plane("relay", "gateway.egress.plane.relay", inflight, denied, denied_family_present)
    _render_adapter(inflight, denied, denied_family_present, present=bool(adapter_up))

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
        # Validate against the plane's closed enum and get the i18n description.
        # Metric label VALUES stay English (reason token) so operators can correlate
        # with Prometheus — the human-readable description follows in parentheses.
        description = _reason_description(plane, reason)
        parts.append(f"{reason}={count} ({description})")
    return "  ".join(parts)


def _reason_description(plane: str, reason: str) -> str:
    """Validate ``reason`` against the plane's closed enum and return the i18n description.

    Raises ``ValueError`` on an unknown reason token so metric drift fails loud
    (display-side payload-blindness — hard rule #7).
    """
    if plane in {"proxy", "adapter"}:
        if reason not in _PROXY_REASONS:
            raise ValueError(f"unknown egress deny reason {reason!r} for plane {plane!r}")
        return t(proxy_reason_key(EgressDenyReason(reason)))
    if reason not in _RELAY_REASONS:
        raise ValueError(f"unknown egress deny reason {reason!r} for plane {plane!r}")
    return t(relay_reason_key(EgressRelayDenyReason(reason)))


def _render_adapter(
    inflight: dict[str, float],
    denied: dict[str, dict[str, float]],
    denied_family_present: bool,
    *,
    present: bool,
) -> None:
    if not present:
        typer.echo(t("gateway.egress.plane.adapter") + "  " + t("gateway.egress.not_configured"))
        return
    _render_plane(
        "adapter", "gateway.egress.plane.adapter", inflight, denied, denied_family_present
    )


def _render_allowlists() -> None:
    """Print a per-plane allowlist summary line (config read, not a scrape).

    Each plane's allowlist is derived from live env/config — the same derivation the
    gateway uses at boot — so the printed set cannot drift from what the proxy/relay
    actually enforces.
    """
    # Provider proxy allowlist (anthropic + deepseek).
    try:
        from alfred.egress.allowlist import provider_egress_allowlist
        from alfred.gateway.egress_proxy import resolve_deepseek_base_url

        proxy_al = provider_egress_allowlist(resolve_deepseek_base_url())
        proxy_entries = sorted(f"{h}:{p}" for h, p in proxy_al)
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " proxy: "
            + (", ".join(proxy_entries) if proxy_entries else t("gateway.egress.allowlist_empty"))
        )
    except Exception as exc:  # degrade loudly — never crash the report
        log.warning("gateway.egress.allowlist_unresolved", plane="proxy", error=repr(exc))
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " proxy: "
            + t("gateway.egress.allowlist_unresolved")
        )

    # Tool-egress relay allowlist.
    try:
        from alfred.gateway.egress_relay import resolve_tool_egress_allowlist

        relay_al = resolve_tool_egress_allowlist()
        relay_entries = sorted(f"{h}:{p}" for h, p in relay_al)
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " relay: "
            + (", ".join(relay_entries) if relay_entries else t("gateway.egress.allowlist_empty"))
        )
    except Exception as exc:
        log.warning("gateway.egress.allowlist_unresolved", plane="relay", error=repr(exc))
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " relay: "
            + t("gateway.egress.allowlist_unresolved")
        )

    # Discord adapter allowlist.
    try:
        from alfred.egress.allowlist import discord_egress_allowlist

        discord_al = discord_egress_allowlist()
        exact_entries = sorted(f"{h}:{p}" for h, p in discord_al.exact)
        suffix_entries = sorted(f"*.{h}:{p}" for h, p in discord_al.suffix_bases)
        all_entries = exact_entries + suffix_entries
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " adapter(discord): "
            + (", ".join(all_entries) if all_entries else t("gateway.egress.allowlist_empty"))
        )
    except Exception as exc:
        log.warning("gateway.egress.allowlist_unresolved", plane="adapter", error=repr(exc))
        typer.echo(
            t("gateway.egress.allowlist_label")
            + " adapter(discord): "
            + t("gateway.egress.allowlist_unresolved")
        )


__all__ = ["egress_status"]
