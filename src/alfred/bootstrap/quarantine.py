"""Bootstrap helpers for the quarantined-LLM subsystem.

AI-3 fix: ``config/routing.yaml`` documents that the privileged provider
and the quarantined provider "MUST differ" by default (spec §5.4, PRD
§6.4). The prior code had no startup check enforcing that invariant —
an operator who set both ``[quarantine] provider`` and the privileged
provider to the same id would boot a system where the dual-LLM split
is structurally a single-LLM split. This module is the structural
backstop: every code path that wires the quarantined-LLM client at
bootstrap MUST consult :func:`assert_provider_separation` before
returning a ready router.

This helper is deliberately tiny and import-light — bootstrap modules
should be cheap to import in the test / mypy / ruff context, and
pulling in the routing.yaml loader here would force every test that
constructs a router-double to either depend on the loader or stub it.

The assertion is a plain :class:`SystemExit`-via-:class:`AlfredError`
because a structurally-broken trust-tier split is not recoverable at
runtime — the operator must fix the config and restart. We surface a
t() string so the operator's locale wins.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t


def assert_provider_separation(
    *,
    privileged_provider_id: str,
    quarantined_provider_id: str,
) -> None:
    """Refuse to boot when the privileged and quarantined providers match.

    Spec §5.4 / PRD §6.4: the dual-LLM split is the structural defence
    against a single compromised provider observing both privileged
    state and T3 content. Allowing the same provider to handle both
    sides collapses the defence; this assertion is the startup-time
    enforcement.

    Closed-set: provider ids are normalised via ``.strip().lower()``
    before the comparison so an accidental case / whitespace mismatch
    in routing.yaml does not silently pass the check. Empty / blank
    ids on either side fail too — the operator must declare BOTH
    providers explicitly.

    Raises :class:`AlfredError` with a t() catalogue message; callers
    propagate this to the operator-facing CLI surface and the bootstrap
    refuses to continue. We deliberately do NOT log the offending
    provider id beyond the t() interpolation — the same string lands
    in the audit-log family once the routing.yaml loader is wired
    (slice 4+), at which point this helper grows an audit-emit arm.
    """
    privileged_normalised = privileged_provider_id.strip().lower()
    quarantined_normalised = quarantined_provider_id.strip().lower()
    if not privileged_normalised or not quarantined_normalised:
        raise AlfredError(t("bootstrap.providers_blank_error"))
    if privileged_normalised == quarantined_normalised:
        raise AlfredError(
            t(
                "bootstrap.providers_same_error",
                provider=privileged_normalised,
            )
        )
