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


def provider_ids_collide(a: str, b: str) -> bool:
    """Return ``True`` when two provider ids name the SAME provider.

    The single definition of "same provider" for the whole codebase (#586). Extracted
    so the two call sites that need it — :func:`assert_provider_separation` below (the
    ``require_quarantine_provider_separation=True`` refuse path) and the daemon boot
    graph's ``require_quarantine_provider_separation=False`` *warn* path in
    ``alfred.cli.daemon._comms_boot`` — cannot silently disagree about what a collision
    IS. Before this helper the warn path re-implemented the normalisation inline; two
    copies of a security predicate drift, and the drift is silent in the direction that
    matters (a collision the warn path fails to notice is a dual-LLM split quietly
    collapsed with no operator-facing signal at all).

    Normalisation is ``.strip().lower()`` on both sides, so an accidental case /
    whitespace mismatch in an operator's ``.env`` (``"DeepSeek"`` vs ``"deepseek "``)
    does not read as two different providers.

    Note the blank case: two blank ids normalise equal and therefore DO collide by this
    predicate. :func:`assert_provider_separation` never reaches that outcome — it
    rejects a blank id on either side first, with its own distinct message — so the
    helper's blank behaviour is only observable on the warn path, where "both undeclared"
    is correctly reported as a non-separated configuration rather than passed over.
    """
    return a.strip().lower() == b.strip().lower()


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
    before the comparison — delegated to :func:`provider_ids_collide`
    above, the ONE definition of "same provider", shared with the
    daemon boot graph's not-required warn path — so an accidental
    case / whitespace mismatch in routing.yaml does not silently pass
    the check. Empty / blank ids on either side fail too, checked
    HERE and before the collision test: the operator must declare BOTH
    providers explicitly, and "both undeclared" must not be reported
    as the (different, actionable-in-a-different-way) same-provider
    error.

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
    if provider_ids_collide(privileged_provider_id, quarantined_provider_id):
        raise AlfredError(
            t(
                "bootstrap.providers_same_error",
                provider=privileged_normalised,
            )
        )
