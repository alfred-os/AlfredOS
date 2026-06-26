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


__all__ = ["_register"]
