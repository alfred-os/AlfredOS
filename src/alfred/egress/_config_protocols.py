"""Narrow read-only config Protocols for the egress subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol

# Future egress-plane config Protocols (e.g. an ``EgressRelayConfig`` reading
# ``egress_relay_url`` for the web_fetch/relay batch, #351 PR4) belong in THIS module —
# don't mint a second per-field module.


class EgressProxyConfig(Protocol):
    """The config surface ``EgressClient.from_settings`` reads: the L7-proxy URL.

    Producer invariant: ``Settings.egress_proxy_url`` is normalized by
    ``_normalize_egress_proxy_url`` (``mode="before"``) so a blank/whitespace value
    deserializes to ``None`` — a ``Settings``-sourced value is therefore either a
    non-blank URL or ``None``, never ``""``. A plain stub bypasses that normalizer, so
    a stub *may* legally supply ``""``; the consumer therefore self-defends
    (``from_settings`` treats any falsy value — ``None`` or ``""`` — as fail-closed,
    G7-3, ADR-0042). The "no route without a proxy" fail-closed invariant is owned by
    ``EgressClient.from_settings``, not by this config surface.
    """

    @property
    def egress_proxy_url(self) -> str | None: ...
