"""Hook subsystem error taxonomy — see spec §3.1.

Three exception classes rooted at :class:`alfred.errors.AlfredError`:

* :class:`HookError` — the hook-subsystem root. The dispatcher in Task-10
  catches this for the swallow-vs-re-raise decision; the orchestrator's
  PR-B ``except`` arm catches the broader :class:`AlfredError`.
* :class:`HookRefusal` — a deliberate refusal by a pre-hook (DLP policy,
  capability denial, trust-tier mismatch). Keyword-only ``__init__``
  stores all four audit-attribution fields verbatim. The user-visible
  message is built through :func:`alfred.i18n.t` so operator output
  respects the active locale (i18n rule #1).
* :class:`HookSubscriberError` — wraps an unexpected exception from a
  registered subscriber. The actual ``raise ... from exc`` site lives
  in Task-10's ``_run_chain``; this slice ships the class plus the
  :meth:`HookSubscriberError.from_subscriber` constructor so the
  call-site only has to supply the subscriber name, correlation id, and
  the upstream exception. The message is built via :func:`alfred.i18n.t`
  against the ``hooks.subscriber_error`` catalog entry.

Conventions pinned by ``tests/unit/hooks/test_errors.py``:

* Hard rule (CLAUDE.md security #7): no silent failures in security
  paths — the catalog-key resolution test asserts a *rendered* string,
  not the bare-key fallback the translator returns for missing entries.
* Hard rule (CLAUDE.md i18n #1): every operator-facing string goes
  through ``t()`` — every constructor and helper here renders via ``t()``
  before passing the message up to :class:`HookError.__init__`.
* Hard rule (CLAUDE.md i18n #4): the three msgid/msgstr pairs land
  atomically with this source file. Because ``pybabel update`` only
  keeps msgids that have a live ``t("key", ...)`` call-site in the
  source, all three keys are referenced from real call-sites in this
  module (``HookRefusal.__init__``,
  :func:`subscriber_must_be_async_message`, and
  :meth:`HookSubscriberError.from_subscriber`) — Task-7's decorator and
  Task-10's dispatcher will import the helpers so the call-sites stay
  rooted here, not duplicated.

Forward-compat: Task-7 (the decorator) raises
:class:`HookSubscriberError` against the ``hooks.subscriber_must_be_async``
catalog entry when a sync function is registered. The helper
:func:`subscriber_must_be_async_message` renders that key in this
module so pybabel keeps it as a live catalog entry without Task-7
having landed yet.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable

from alfred.errors import AlfredError
from alfred.i18n import t


class HookError(AlfredError):
    """Root of the hook subsystem error hierarchy.

    The dispatcher catches this in Task-10's ``_run_chain`` to decide
    swallow-vs-re-raise per stage; downstream code catching
    :class:`AlfredError` picks up hook errors uniformly.
    """


class HookRefusal(HookError):  # noqa: N818  -- spec §3.1 names this class without an Error suffix; rename would break the PRD/spec/plan contract and every test that constructs HookRefusal(...).
    """A pre-hook deliberately refused the action.

    Raised by a pre-hook to abort the action body cleanly (DLP block,
    capability denied, trust-tier mismatch, persona refusal). The audit
    row in Task-10 reads ``hook_id``, ``action_id``, ``reason``, and
    ``correlation_id`` directly off the attribute — they are part of the
    type's structural contract, not just message-format inputs.

    The keyword-only signature mirrors the verbatim spec §3.1 contract
    so a caller cannot accidentally swap, say, ``action_id`` and
    ``hook_id`` via positional args.
    """

    # Explicit attribute typing so mypy --strict sees the public fields
    # the dispatcher / audit writer rely on, distinct from any hidden
    # state on the Exception base.
    hook_id: str
    action_id: str
    reason: str
    correlation_id: str

    def __init__(
        self,
        *,
        hook_id: str,
        action_id: str,
        reason: str,
        correlation_id: str,
    ) -> None:
        # Store the four fields BEFORE building the message so a debugger
        # stopped in `t()` would still see them on `self`. Note the
        # catalog template (locale/en/LC_MESSAGES/alfred.po →
        # `hooks.refusal`) deliberately does NOT embed `correlation_id`
        # in the operator-facing message — the id stays on the
        # attribute for the audit row only. The test
        # `test_hook_refusal_does_not_leak_correlation_id_into_message`
        # pins that no-leak.
        self.hook_id = hook_id
        self.action_id = action_id
        self.reason = reason
        self.correlation_id = correlation_id
        message = t(
            "hooks.refusal",
            hook_id=hook_id,
            action_id=action_id,
            reason=reason,
        )
        super().__init__(message)


def subscriber_must_be_async_message(*, name: str) -> str:
    """Render the ``hooks.subscriber_must_be_async`` operator-facing string.

    Task-7's :func:`@hook` decorator calls this when a sync function is
    registered. The call-site reads:

    .. code-block:: python

        from alfred.hooks.errors import (
            HookSubscriberError,
            subscriber_must_be_async_message,
        )
        raise HookSubscriberError(subscriber_must_be_async_message(name=fn.__name__))

    Living in :mod:`alfred.hooks.errors` rather than the decorator's
    module keeps every hook-subsystem catalog key co-located with the
    error taxonomy — pybabel sees one source-of-truth file for the
    ``hooks.*`` msgids.
    """
    return t("hooks.subscriber_must_be_async", name=name)


class HookSubscriberError(HookError):
    """Wraps an unexpected exception from a registered hook subscriber.

    The intended usage in Task-10's ``_run_chain`` is::

        try:
            await subscriber(context)
        except Exception as exc:
            raise HookSubscriberError.from_subscriber(
                name=subscriber.__name__,
                correlation_id=context.correlation_id,
            ) from exc

    The ``raise ... from exc`` preserves ``__cause__`` so the audit
    row's "see the audit log" pointer can follow the chained traceback
    to the original exception. The plain ``HookSubscriberError(msg)``
    constructor is also supported for cases that already have a
    rendered message in hand (e.g. Task-7's decorator passes
    :func:`subscriber_must_be_async_message`'s output).
    """

    @classmethod
    def from_subscriber(
        cls,
        *,
        name: str,
        correlation_id: str,
    ) -> HookSubscriberError:
        """Build a subscriber-error with the standard rendered message.

        Wrappers in Task-10 use this so the catalog key is referenced
        in exactly one place; the call-site only knows the subscriber
        name and the correlation id.
        """
        message = t(
            "hooks.subscriber_error",
            name=name,
            correlation_id=correlation_id,
        )
        return cls(message)


# ──────────────────────────────────────────────────────────────────────
# #119 register_hookpoint / register message helpers (i18n via t())
# ──────────────────────────────────────────────────────────────────────
#
# Four operator-facing message templates rendered through ``t()`` so the
# new register-time refusal raises (registry.py) honour the i18n rule
# (CLAUDE.md i18n hard rule #1 — every operator-facing string goes
# through ``t()``). Each helper carries the call-site attribution data
# the catalog template interpolates; placing them here keeps every
# ``hooks.*`` msgid co-located in one source-of-truth file (pybabel
# behaviour + i18n rule #4 — atomic catalog landing).


def hookpoint_drift_message(
    *,
    name: str,
    stored: object,
    new: object,
) -> str:
    """Render the ``hooks.hookpoint_drift`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register_hookpoint`
    when a publisher attempts to re-declare a hookpoint with different
    metadata. The attribution carries BOTH the stored and the new
    metadata so the operator can grep both sites and reconcile.

    The catalog template (``hooks.hookpoint_drift``) interpolates the
    three fields; ``stored`` and ``new`` are ``repr``-rendered at the
    catalog seam so the locale switch never loses the
    ``HookpointMeta(...)`` shape that makes the diff readable.
    """
    return t(
        "hooks.hookpoint_drift",
        name=name,
        stored=repr(stored),
        new=repr(new),
    )


def unknown_tier_message(
    *,
    tier: str,
    subscriber_name: str,
    hookpoint: str,
    valid_tiers: Iterable[str],
) -> str:
    """Render the ``hooks.unknown_tier`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register` when
    the requested ``tier`` is not one of the three known values
    (``"system"`` / ``"operator"`` / ``"user-plugin"``). The attribution
    includes the subscriber name and the hookpoint so the operator
    can locate the typo in source.

    Args:
        tier: The unknown tier string the caller passed.
        subscriber_name: ``hook_fn.__qualname__`` of the offending
            subscriber.
        hookpoint: The hookpoint identifier (stem form) the subscriber was
            registering against.
        valid_tiers: The known-tier iterable surfaced verbatim in the
            message so the operator sees the legal alternatives.
    """
    return t(
        "hooks.unknown_tier",
        tier=tier,
        subscriber_name=subscriber_name,
        hookpoint=hookpoint,
        valid_tiers=repr(sorted(valid_tiers)),
    )


def hookpoint_not_declared_message(
    *,
    name: str,
    declared_names: Iterable[str] = (),
) -> str:
    """Render the ``hooks.hookpoint_not_declared`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register` when
    a subscriber attempts to register against a hookpoint that no
    publisher has declared.

    The rewritten message (Group F of the #119 review):

    * **Publisher / subscriber distinction** — the message explicitly
      tells the reader that the PUBLISHER of the hookpoint must call
      ``register_hookpoint`` at module init, BEFORE any subscriber
      attempts to register. This collapses the two shapes a
      subscriber-side reader could otherwise guess at ("did I get the
      name wrong?" vs "did the publisher forget to declare?").
    * **Closest-match suggestion** — when ``name`` is within edit-
      distance 2 of any declared hookpoint, the message appends a
      ``Did you mean: 'X'?`` hint via :func:`difflib.get_close_matches`.
      Mirrors the surface of CLI typo-suggestion error messages so the
      reader's first reaction is "try the suggestion" not "re-read the
      paragraph".

    Args:
        name: The undeclared hookpoint the subscriber tried to
            register against.
        declared_names: The currently-declared hookpoint names. Empty
            iterable disables the closest-match suggestion (the
            message still carries the publisher/subscriber hint).
    """
    suggestion = ""
    matches = difflib.get_close_matches(name, declared_names, n=1, cutoff=0.6)
    if matches:
        suggestion = t("hooks.hookpoint_not_declared.did_you_mean", suggestion=matches[0])
    return t(
        "hooks.hookpoint_not_declared",
        name=name,
        suggestion=suggestion,
    )


def tier_not_subscribable_message(
    *,
    tier: str,
    hookpoint: str,
    subscribable_tiers: Iterable[str],
) -> str:
    """Render the ``hooks.tier_not_subscribable`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register` when
    a subscriber's tier is rejected by the publisher's declared
    ``subscribable_tiers``. The attribution surfaces both the
    rejected tier AND the allowed set so the operator can either
    re-tier the subscriber or amend the publisher's declaration.

    Args:
        tier: The rejected tier the subscriber declared.
        hookpoint: The hookpoint identifier (stem form).
        subscribable_tiers: The publisher-declared allow-list,
            rendered as a sorted list for stable comparison.
    """
    return t(
        "hooks.tier_not_subscribable",
        tier=tier,
        hookpoint=hookpoint,
        subscribable_tiers=repr(sorted(subscribable_tiers)),
    )


def dispatch_undeclared_hookpoint_message(
    *,
    name: str,
    kind: str,
    correlation_id: str,
) -> str:
    """Render the ``hooks.dispatch_undeclared_hookpoint`` operator-facing string.

    Called by :func:`alfred.hooks.invoke._enforce_meta_drift` at dispatch
    time, on the strict-mode arm where the hookpoint was never declared
    AND register-time enforcement should have prevented the subscriber
    from landing. This is the "internal inconsistency" path — both the
    publisher's :meth:`HookRegistry.register_hookpoint` call AND the
    subscriber's :meth:`HookRegistry.register` call should have
    serialised the typo at module import time; reaching this branch
    means something downstream re-imported a publisher module or the
    registry singleton was swapped mid-run.

    The audit row goes out BEFORE this message is rendered (see the
    ``HOOKS_TIER_REJECTED`` emit at the call-site); this helper is the
    operator-facing tail that surfaces on the raised
    :class:`HookError`'s ``str()`` representation.

    Args:
        name: The hookpoint identifier (stem form) that was dispatched but
            never declared.
        kind: The lifecycle stage (``"pre"`` / ``"post"`` / ``"error"``
            / ``"cancel"``) — surfaces on both the audit row and the
            message so the operator can correlate the two attributions.
        correlation_id: Cross-system trace id — surfaces on the message
            so an operator reading the raised exception can grep the
            audit log for the matching row.
    """
    return t(
        "hooks.dispatch_undeclared_hookpoint",
        name=name,
        kind=kind,
        correlation_id=correlation_id,
    )


def publisher_drift_message(
    *,
    name: str,
    drift_kind: str,
    declared_subscribable_tiers: Iterable[str],
    declared_refusable_tiers: Iterable[str],
    declared_fail_closed: bool,
    invoked_subscribable_tiers: Iterable[str],
    invoked_refusable_tiers: Iterable[str] | None,
    invoked_fail_closed: bool | None,
) -> str:
    """Render the ``hooks.publisher_drift`` operator-facing string.

    Called by :func:`alfred.hooks.invoke._enforce_meta_drift` when the
    publisher's invoke-time args disagree with the
    :class:`HookpointMeta` the publisher declared at module init. The
    catalog template surfaces BOTH sides of the disagreement so the
    operator can grep both the declaration site and the invoke site
    and reconcile.

    ``drift_kind`` is the FIRST field detected as disagreeing (the
    detector walks ``subscribable_tiers`` → ``refusable_tiers`` →
    ``fail_closed``); the message carries the full state of all three
    fields so the operator can see whether more than one field drifted.

    Args:
        name: The hookpoint identifier (stem form).
        drift_kind: The first-detected disagreeing field
            (``"subscribable_tiers"`` / ``"refusable_tiers"`` /
            ``"fail_closed"``) — surfaces on both the audit row and
            the message so the two attributions correlate.
        declared_subscribable_tiers: From the stored
            :class:`HookpointMeta`. Rendered as a sorted list.
        declared_refusable_tiers: From the stored
            :class:`HookpointMeta`. Rendered as a sorted list.
        declared_fail_closed: From the stored :class:`HookpointMeta`.
        invoked_subscribable_tiers: The publisher's invoke-time arg.
            Rendered as a sorted list.
        invoked_refusable_tiers: The publisher's invoke-time arg,
            ``None`` when the handler does not pass this field.
        invoked_fail_closed: The publisher's invoke-time arg, ``None``
            when the handler does not pass this field.
    """
    invoked_refusable_repr = (
        repr(sorted(invoked_refusable_tiers)) if invoked_refusable_tiers is not None else repr(None)
    )
    return t(
        "hooks.publisher_drift",
        name=name,
        drift_kind=drift_kind,
        declared_subscribable_tiers=repr(sorted(declared_subscribable_tiers)),
        declared_refusable_tiers=repr(sorted(declared_refusable_tiers)),
        declared_fail_closed=repr(declared_fail_closed),
        invoked_subscribable_tiers=repr(sorted(invoked_subscribable_tiers)),
        invoked_refusable_tiers=invoked_refusable_repr,
        invoked_fail_closed=repr(invoked_fail_closed),
    )


def unknown_tier_in_declaration_message(
    *,
    hookpoint: str,
    unknown_tiers: Iterable[str],
    valid_tiers: Iterable[str],
) -> str:
    """Render the ``hooks.unknown_tier_in_declaration`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register_hookpoint`
    when a publisher's :attr:`HookpointMeta.subscribable_tiers` or
    :attr:`HookpointMeta.refusable_tiers` contains one or more tier
    strings that are not in the known-tier vocabulary
    (``"system"`` / ``"operator"`` / ``"user-plugin"``).

    The high-blast shape this guards against (CR cycle-1 MAJ-3): a
    publisher with ``subscribable_tiers={"operatior"}`` (typo) would
    silently disable the register-time tier-allow-list gate at every
    subscriber site — the typo string never matches any subscriber's
    requested tier so every register call refuses. Without
    declaration-time validation the typo is invisible until the first
    subscriber registers AND the operator notices the unexpected
    refusal. Declaration-time validation surfaces the typo at module
    init.

    Args:
        hookpoint: The hookpoint identifier (stem form) the publisher is
            declaring against.
        unknown_tiers: The tier strings the publisher passed that are
            not in the known-tier vocabulary.
        valid_tiers: The known-tier vocabulary, rendered verbatim so
            the operator sees the legal alternatives.
    """
    return t(
        "hooks.unknown_tier_in_declaration",
        hookpoint=hookpoint,
        unknown_tiers=repr(sorted(unknown_tiers)),
        valid_tiers=repr(sorted(valid_tiers)),
    )


def carrier_tier_required_message(*, hookpoint: str) -> str:
    """Render the ``hooks.carrier_tier_required`` operator-facing string.

    Called by :meth:`alfred.hooks.registry.HookRegistry.register_hookpoint`
    when a publisher passes ``carrier_tier=None`` for a hookpoint NOT
    on the meta-hookpoint allow-list. Only ``hooks.carrier_substituted``
    and ``hooks.carrier_substitution_refused`` may carry
    ``carrier_tier=None`` — every other hookpoint declares its
    upper-bound tier so the Slice-4 tier-upgrade guard has a
    fixed point to compare against (ADR-0022 PR-S4-3).

    Args:
        hookpoint: The hookpoint identifier the publisher is declaring.
    """
    return t("hooks.carrier_tier_required", hookpoint=hookpoint)


def carrier_tier_must_be_none_for_meta_hookpoint_message(*, hookpoint: str) -> str:
    """Render the ``hooks.carrier_tier_must_be_none_for_meta_hookpoint``
    operator-facing string.

    Symmetric guard to :func:`carrier_tier_required_message`: a
    publisher declaring a meta-hookpoint (``hooks.carrier_substituted``
    / ``hooks.carrier_substitution_refused``) MUST set
    ``carrier_tier=None`` to keep the recursion guard intact. A
    non-``None`` value would let the meta-hookpoint substitute its
    own error (ADR-0022 PR-S4-3).

    Args:
        hookpoint: The hookpoint identifier the publisher is declaring.
    """
    return t(
        "hooks.carrier_tier_must_be_none_for_meta_hookpoint",
        hookpoint=hookpoint,
    )


def allow_error_substitution_must_be_false_for_meta_hookpoint_message(
    *, hookpoint: str
) -> str:
    """Render the ``hooks.allow_error_substitution_must_be_false_for_meta_hookpoint``
    operator-facing string.

    Meta-hookpoints MUST carry ``allow_error_substitution=False`` so
    a subscriber against the meta-hookpoint cannot substitute the
    meta-event's payload. Belt-and-braces alongside the
    ``carrier_tier=None`` guard (ADR-0022 PR-S4-3).

    Args:
        hookpoint: The hookpoint identifier the publisher is declaring.
    """
    return t(
        "hooks.allow_error_substitution_must_be_false_for_meta_hookpoint",
        hookpoint=hookpoint,
    )
