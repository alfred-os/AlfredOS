"""Spec-C (#333) egress catalog-key reservation.

G7-1b's gateway egress audit renders each denial reason via
``t(reason_i18n_key(reason))`` — a dict-style ``f"{prefix}{reason.value}"``
dereference (:func:`alfred.gateway.egress_audit.reason_i18n_key`), so the
literal msgid is invisible to ``pybabel extract`` at the call site. Without a
static reference here ``pybabel update`` would mark the keys obsolete on the
next run, dropping them from the compiled ``.mo`` and tripping the
``i18n catalog drift`` gate + the ``G7_EGRESS_KEYS`` catalog test.

Each ``t(...)`` below is a static reference Babel extracts; ``_register`` is
never called at runtime. Follows the ``_spec_b_reserve`` ingress-reason pattern.
"""

from __future__ import annotations

from alfred.i18n import t


def _register() -> None:
    """Reference every Spec-C egress reason key so pybabel sees them as used.

    The reason TOKENS stay stable English identifiers (the closed-vocab
    :class:`alfred.gateway.egress_audit.EgressDenyReason` values); only these
    operator-rendered PRESENTATIONS are localised.
    """
    t("gateway.egress.denied.destination_not_allowlisted")
    t("gateway.egress.denied.literal_ip_target")
    t("gateway.egress.denied.resolved_ip_not_global")
    t("gateway.egress.denied.malformed_connect")
    # G7-2b: the mode-(b) inspecting-relay deny-reason presentations. Rendered via
    # ``t(reason_i18n_key(reason))`` (a ``f"{prefix}{reason.value}"`` dereference in
    # ``alfred.gateway.egress_relay_audit``), so the literal msgids are invisible to
    # ``pybabel extract`` at the call site and must be anchored here.
    t("gateway.egress.relay_denied.destination_not_allowlisted")
    t("gateway.egress.relay_denied.literal_ip_target")
    t("gateway.egress.relay_denied.resolved_ip_not_global")
    t("gateway.egress.relay_denied.dlp_redacted")
    t("gateway.egress.relay_denied.canary_tripped")
    t("gateway.egress.relay_denied.response_too_large")
    t("gateway.egress.relay_denied.malformed_envelope")
    t("gateway.egress.relay_denied.upstream_redirect_refused")
    # G7-2.5 Task 4: inbound canary trip on a web.fetch response (in-core D1 seam).
    # Rendered inside ``InboundCanaryTripped.__init__`` via
    # ``t("egress.inbound_canary_tripped", destination=..., egress_id=...)``.
    # Also a literal t() call in response_inspection.py, so pybabel would extract
    # it directly — anchored here as a belt-and-braces guard matching the outbound
    # ``egress.outbound_canary_tripped`` precedent.
    t("egress.inbound_canary_tripped")
    # G7-5 PR-A Task 4: ``alfred gateway egress`` plane header keys.  Passed as a
    # variable ``header_key`` argument to ``_render_plane()``, which calls
    # ``t(header_key)`` — the literal msgids are invisible to pybabel at the call
    # site, so they are anchored here to prevent pybabel update from marking them
    # obsolete and dropping them from the compiled ``.mo``.
    t("gateway.egress.plane.proxy")
    t("gateway.egress.plane.relay")


__all__ = ["_register"]
