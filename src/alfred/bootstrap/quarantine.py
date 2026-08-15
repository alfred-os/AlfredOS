"""Bootstrap helpers for the quarantined-LLM subsystem.

AI-3 fix: ``config/routing.yaml`` documents that the privileged provider
and the quarantined provider "MUST differ" by default (spec §5.4, PRD
§6.4). The prior code had no startup check enforcing that invariant —
an operator who set both ``[quarantine] provider`` and the privileged
provider to the same id would boot a system where the dual-LLM split
is structurally a single-LLM split. This module supplies that check,
:func:`assert_provider_separation` — but it is NOT a universal backstop
consulted by every bootstrap path. In this codebase only the daemon boot
path calls it (``alfred.cli.daemon._comms_boot.enforce_quarantine_
provider_separation``, run unconditionally on every ``alfred daemon
start`` / ``docker compose up``), and even there it REFUSES only when the
operator opts in with ``ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=
true`` (ADR-0064) — the default is warn-only. ``alfred.cli._bootstrap.
build_router``, the function every OTHER top-level command (``chat``,
``login``, ``status``, ...) goes through to get a ready router, never
calls this module at all (issue #590 tracks closing that gap).

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


class ProviderIdBlankError(AlfredError):
    """A blank privileged or quarantined provider id reached the separation check.

    Round-5 review fleet (1G): distinct from :class:`ProviderSeparationViolatedError`
    below — this is a MISSING-CONFIG fault ("the operator did not declare a provider"),
    not a collision. Splitting them lets a caller (``_comms_boot.py``'s unconditional
    per-boot gate) catch the collision specifically without also catching this one — the
    12-line comment that used to sit at that catch site, explaining why relabelling
    every ``AlfredError`` from this module as a collision was "only honest because a
    collision is the sole thing that can still reach that line," is no longer needed:
    the type now says what the comment asserted.
    """


class ProviderSeparationViolatedError(AlfredError):
    """The privileged and quarantined provider ids collide — separation required.

    Round-5 review fleet (1G): behaviour-preserving for every existing
    ``except AlfredError`` caller (both are still ``AlfredError`` subclasses); this only
    makes the SHAPE of what :func:`assert_provider_separation` raises independently
    checkable, rather than resting on a caller's own bare relabel of "the only
    ``AlfredError`` this function can still raise here."
    """


def provider_ids_collide(a: str, b: str) -> bool:
    """Return ``True`` when two provider ids name the SAME provider.

    The single definition of "same provider" for the whole codebase (#586). Extracted
    so the two call sites that need it — :func:`assert_provider_separation` below (the
    ``require_quarantine_provider_separation=True`` refuse path) and the
    ``require_quarantine_provider_separation=False`` *warn* path in
    ``alfred.cli.daemon._comms_boot.enforce_quarantine_provider_separation`` (the gate
    the daemon runs on EVERY boot, not the comms-gated boot graph) — cannot silently
    disagree about what a collision IS. Before this helper the warn path re-implemented
    the normalisation inline; two
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

    As of the round-2 fix wave neither id can actually BE blank on the daemon boot path:
    both ``Settings.quarantine_provider`` and ``Settings.primary_provider`` are
    ``Literal`` fields, so a blank (or any other out-of-set) value refuses at Settings
    construction rather than reaching the separation gate and getting relabelled as a
    collision. The blank arms here are retained as defence-in-depth for callers that do
    not come through ``Settings`` — this helper is deliberately import-light and
    config-agnostic.
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
    not-required warn path in the daemon's unconditional per-boot
    separation gate
    (``alfred.cli.daemon._comms_boot.enforce_quarantine_provider_separation``)
    — so an accidental case / whitespace mismatch in routing.yaml does
    not silently pass the check. Empty / blank ids on either side fail too, checked
    HERE and before the collision test: the operator must declare BOTH
    providers explicitly, and "both undeclared" must not be reported
    as the (different, actionable-in-a-different-way) same-provider
    error.

    Raises :class:`ProviderIdBlankError` (blank arm) or
    :class:`ProviderSeparationViolatedError` (collision arm) — both
    :class:`AlfredError` subclasses (round-5 review fleet, 1G) — with a t() catalogue
    message; callers propagate this to the operator-facing CLI surface and the
    bootstrap refuses to continue. We deliberately do NOT log the offending
    provider id beyond the t() interpolation — the same string lands
    in the audit-log family once the routing.yaml loader is wired
    (slice 4+), at which point this helper grows an audit-emit arm.
    """
    privileged_normalised = privileged_provider_id.strip().lower()
    quarantined_normalised = quarantined_provider_id.strip().lower()
    if not privileged_normalised or not quarantined_normalised:
        raise ProviderIdBlankError(t("bootstrap.providers_blank_error"))
    if provider_ids_collide(privileged_provider_id, quarantined_provider_id):
        raise ProviderSeparationViolatedError(
            t(
                "bootstrap.providers_same_error",
                provider=privileged_normalised,
            )
        )
