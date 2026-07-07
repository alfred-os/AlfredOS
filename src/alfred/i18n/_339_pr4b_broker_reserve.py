"""#339 PR4b-broker (#347 blocker 4) catalog-key reservation.

``dispatch_web_fetch``'s local ``_refuse(*, dlp_scan_result, message_key)``
helper (:mod:`alfred.plugins.web_fetch.fetch_dispatcher`) renders every
pre-network refusal via ``t(message_key)``, where ``message_key`` is a
parameter — the literal msgid string is passed at each *call site* of
``_refuse``, not directly to ``t()`` itself, so it is invisible to
``pybabel extract`` there. Without a static reference here, the three keys
below would be marked ``#~ obsolete`` on the next ``pybabel update``,
dropping them from the compiled ``.mo`` and tripping the CI
``i18n catalog drift`` gate. Follows the ``_spec_c_reserve`` /
``_spec_b_reserve`` indirect-dereference precedent (see e.g.
``alfred.gateway.egress_audit``'s ``t(reason_i18n_key(reason))``).

Note ``web.fetch.error.url_secret_refused`` is included even though it
predates PR4b-broker: FIX-10 (DRY) refactored its refusal to route through
the same ``_refuse`` helper, so its literal ``t()`` call site
(``fetch_dispatcher.py:386`` pre-refactor) disappeared too and it needs the
same anchor.

Each ``t(...)`` below is a static reference Babel extracts; ``_register`` is
never called at runtime.
"""

from __future__ import annotations

from alfred.i18n import t


def _register() -> None:
    """Reference every #339 PR4b-broker indirect catalog key so pybabel sees
    them as used.

    Never called at runtime. The real call sites are all
    ``_refuse(message_key=...)`` inside ``dispatch_web_fetch``.
    """
    t("web.fetch.error.url_secret_refused")
    t("web.fetch.error.header_secret_refused")
    t("web.fetch.error.secret_substitution_refused")


__all__ = ["_register"]
