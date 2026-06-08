"""Dispatch-time defense-in-depth re-check for ``subscribable_tiers``
(#119, commit 3).

Pins the spec §6.2 SECOND half — "re-checked at invoke":

   subscribable_tiers — registration-time enforced; **re-checked at
   invoke**

The publisher passes ``subscribable_tiers`` to :func:`invoke` at
dispatch time; the dispatcher consults the registry's declared
allow-list for that hookpoint and audits + fails closed if the two
disagree. The two checks defend against different shapes of bug:

* **Registration-time** (commit 2) — a subscriber wired to a
  hookpoint at a tier the hookpoint's declaration refuses. Caught at
  decoration time before the subscriber ever runs.
* **Dispatch-time** (this file) — a publisher whose invoke-time
  ``subscribable_tiers`` arg drifts away from the declaration the
  publisher itself made at module-init. This is a publisher bug:
  the publisher should have one source of truth for its allow-list;
  if the two disagree, the dispatcher cannot tell which one is
  correct and refuses to run the chain.

This is "publisher-side declaration" defense; the gate-side check (a
subscriber tier the dev/operator gate refused) ran at registration
time. Both pass for a subscriber to actually dispatch.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from alfred.hooks.audit_sink import HOOKS_TIER_REJECTED
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import HookRegistry
from alfred.security.tiers import T3
from tests.unit.hooks.conftest import SpyAuditSink


def _ctx() -> HookContext[Any]:
    """Build a fresh frozen :class:`HookContext` for a synthetic action."""
    return HookContext(
        action_id="test.action",
        hookpoint="test.action",
        input=None,
        correlation_id=uuid4().hex,
        kind="pre",
    )


@pytest.mark.asyncio
async def test_dispatch_detects_publisher_allowlist_drift(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A publisher whose invoke-time ``subscribable_tiers`` differs from
    the registry's declared one emits a :data:`HOOKS_TIER_REJECTED`
    audit row and raises :class:`HookError`.

    The realistic shape: a publisher refactor splits one declaration
    site and one invoke site, then a copy-paste typo flips the
    allow-list at the invoke site (forgetting to update both places).
    The drift defense catches the typo on the next invoke and
    short-circuits the dispatch — no subscribers run, the action body
    sees a hard refusal, the operator gets a loud audit row.

    Verifies both arms:

    1. The audit row event id is :data:`HOOKS_TIER_REJECTED`.
    2. The row carries the declared allow-list AND the publisher's
       (drifted) allow-list so the operator can grep both.
    3. :class:`HookError` propagates — the action body short-circuits.
    """
    # Publisher declares the hookpoint with ``{"system","operator"}``.
    spy_registry_allow_system.register_hookpoint(
        name="drifted",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    # Publisher then invokes with ``{"system"}`` — DIFFERENT allow-list.
    with pytest.raises(HookError, match="subscribable_tiers"):
        await invoke(
            "drifted",
            _ctx(),
            kind="pre",
            subscribable_tiers=frozenset({"system"}),
        )

    # Audit row landed.
    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected one HOOKS_TIER_REJECTED row; got {[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "drifted"
    assert fields["kind"] == "pre"
    # Both sets surface on the row so the operator can grep both
    # declaration sites — this is the LOAD-BEARING attribution for a
    # publisher-side drift.
    assert set(fields["declared_subscribable_tiers"]) == {"system", "operator"}  # type: ignore[arg-type]
    assert set(fields["invoked_subscribable_tiers"]) == {"system"}  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_dispatch_matching_allowlist_runs_chain(
    spy_registry_allow_system: HookRegistry,
) -> None:
    """When the publisher's invoke-time ``subscribable_tiers`` matches
    the declaration, the chain runs normally.

    Positive control on the drift defense — without it the deny test
    above could pass for the wrong reason (e.g. always-fail on drift
    check).
    """
    spy_registry_allow_system.register_hookpoint(
        name="matched",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    # Same allow-list at invoke time. The dispatcher's re-check
    # passes; the chain (empty, zero subscribers) returns the ctx
    # unchanged. Group I now checks ALL three meta fields, so the
    # invoke args must match every field on the declaration to avoid
    # drift.
    ctx = _ctx()
    result = await invoke(
        "matched",
        ctx,
        kind="pre",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    # Returned ctx is the input ctx (modulo for_stage retarget — the
    # hookpoint is rewritten to "matched").
    assert result.hookpoint == "matched"


@pytest.mark.asyncio
async def test_dispatch_undeclared_hookpoint_skips_drift_check(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """When the publisher has NOT declared the hookpoint, the dispatch
    cannot detect drift — the chain proceeds without a re-check.

    This is the permissive-mode bypass: undeclared hookpoints can
    still dispatch (e.g. test fixtures, pre-#119 publishers). The
    register-time strict gate (commit 1) is what catches the typo at
    decoration; if a hookpoint reaches dispatch without a declaration,
    we cannot say whether the publisher's invoke arg is "right".
    Skipping the re-check here is the only sound choice.

    Pinned so a future change that adds an undeclared-warn audit row
    has a test to update.
    """
    # No ``register_hookpoint`` call here. The default
    # :func:`spy_registry_allow_system` fixture is permissive
    # (``strict_declarations=False``) so the dispatch proceeds.
    result = await invoke(
        "never.declared",
        _ctx(),
        kind="pre",
        subscribable_tiers=frozenset({"system"}),
    )
    assert result.hookpoint == "never.declared"
    # No HOOKS_TIER_REJECTED row.
    assert not any(c["event"] == HOOKS_TIER_REJECTED for c in spy_sink.calls)


@pytest.mark.asyncio
async def test_dispatch_drift_check_across_all_kinds(
    spy_registry_allow_system: HookRegistry,
) -> None:
    """The drift re-check fires for every kind — ``pre``, ``post``,
    ``error``, ``cancel``.

    A regression that wires the check only into ``_run_pre`` (the
    most-trafficked handler) would defeat defense-in-depth on the
    other three arms. Parametrize-style test pins all four.
    """
    spy_registry_allow_system.register_hookpoint(
        name="all-kinds",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    # ``pre`` arm.
    with pytest.raises(HookError):
        await invoke(
            "all-kinds",
            _ctx(),
            kind="pre",
            subscribable_tiers=frozenset({"system"}),
        )

    # ``post`` arm.
    with pytest.raises(HookError):
        await invoke(
            "all-kinds",
            _ctx(),
            kind="post",
            subscribable_tiers=frozenset({"system"}),
        )

    # ``error`` arm. Requires an exc; the dispatcher's drift check
    # fires BEFORE the chain walks so the exc is irrelevant — but the
    # public-entry guard demands one.
    with pytest.raises(HookError):
        await invoke(
            "all-kinds",
            _ctx(),
            kind="error",
            subscribable_tiers=frozenset({"system"}),
            exc=ValueError("upstream"),
        )

    # ``cancel`` arm. Same.
    with pytest.raises(HookError):
        await invoke(
            "all-kinds",
            _ctx(),
            kind="cancel",
            subscribable_tiers=frozenset({"system"}),
            exc=ValueError("cancellation"),
        )


# ──────────────────────────────────────────────────────────────────────
# #119 review Group I — full meta drift detection
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_detects_refusable_tiers_drift(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A publisher whose invoke-time ``refusable_tiers`` differs from the
    registry's declared one emits a :data:`HOOKS_TIER_REJECTED` audit
    row (with ``drift_kind=refusable_tiers``) and raises :class:`HookError`.

    Group I extension: the original spec wording centred on
    ``subscribable_tiers``, but a publisher passing the wrong
    ``refusable_tiers`` silently widens which subscribers may refuse on
    the security stage — the same threat shape the
    ``subscribable_tiers`` check defends against, on a different field.
    """
    spy_registry_allow_system.register_hookpoint(
        name="refusable-drift",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    with pytest.raises(HookError, match="refusable_tiers"):
        await invoke(
            "refusable-drift",
            _ctx(),
            kind="pre",
            # Same subscribable_tiers (no drift here)…
            subscribable_tiers=frozenset({"system", "operator"}),
            # …but refusable_tiers drifts: declared {"system"} vs
            # invoked {"system","operator"}.
            refusable_tiers=frozenset({"system", "operator"}),
            fail_closed=True,
        )

    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED row; got {[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["drift_kind"] == "refusable_tiers"
    assert fields["drift_at"] == "dispatch"


@pytest.mark.asyncio
async def test_dispatch_detects_fail_closed_drift(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A publisher whose invoke-time ``fail_closed`` differs from the
    registry's declared one emits a :data:`HOOKS_TIER_REJECTED` audit
    row (with ``drift_kind=fail_closed``) and raises :class:`HookError`.

    This is the high-blast Group I shape — a security-stage publisher
    declared with ``fail_closed=True`` but invokes with
    ``fail_closed=False`` silently disarms CLAUDE.md hard rule #7
    across every subscriber the dispatcher runs. The dispatch-time
    re-check catches the typo on the next invoke and refuses the
    chain.
    """
    spy_registry_allow_system.register_hookpoint(
        name="fail-closed-drift",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    with pytest.raises(HookError, match="fail_closed"):
        await invoke(
            "fail-closed-drift",
            _ctx(),
            kind="pre",
            subscribable_tiers=frozenset({"system", "operator"}),
            refusable_tiers=frozenset({"system"}),
            # The drift: declared True, invoked False.
            fail_closed=False,
        )

    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["drift_kind"] == "fail_closed"
    assert fields["declared_fail_closed"] is True
    assert fields["invoked_fail_closed"] is False


# ──────────────────────────────────────────────────────────────────────
# #119 review Group D — strict / permissive mode behavioural pins
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_undeclared_hookpoint_in_strict_mode_raises(
    spy_sink: SpyAuditSink,
) -> None:
    """An undeclared hookpoint reaching dispatch under strict mode
    raises :class:`HookError`.

    Group D: the prior "silently return when meta is None" behaviour
    combined with ``strict_declarations=False`` on the registry to
    silently no-op BOTH halves of #119. The strict-mode arm now
    fail-loud since reaching dispatch with an undeclared hookpoint
    means the register-time enforcement failed to intercept — an
    internal inconsistency.
    """
    from alfred.hooks.registry import HookRegistry, get_registry, set_registry
    from tests.helpers.gates import make_permissive_fixture_gate

    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        sink=spy_sink,
        strict_declarations=True,
    )
    set_registry(registry)
    try:
        # No register_hookpoint call. Strict mode + undeclared = HookError.
        with pytest.raises(HookError, match="strict mode"):
            await invoke(
                "missing.declaration",
                _ctx(),
                kind="pre",
                subscribable_tiers=frozenset({"system"}),
            )
    finally:
        set_registry(prior)


@pytest.mark.asyncio
async def test_undeclared_hookpoint_in_strict_mode_emits_audit_row(
    spy_sink: SpyAuditSink,
) -> None:
    """The strict-mode-undeclared arm emits
    :data:`HOOKS_TIER_REJECTED` BEFORE raising :class:`HookError`.

    CR cycle-1 alignment: the meta-fields-disagree arm already emits
    an audit row first; the undeclared-in-strict-mode arm previously
    only logged via structlog. Operators monitoring the registry sink
    could not query / alert on this drift shape via the same channel
    as every other dispatch-time drift. This test pins the audit-row
    emission ALONGSIDE the raise so the sink is the one-stop-shop for
    drift attribution.

    Carries the same ``drift_at="dispatch"`` field as every other
    dispatch-time drift row, plus ``drift_kind="undeclared_hookpoint"``
    so operators distinguish this internal-inconsistency shape from
    the field-disagreement shapes.
    """
    from alfred.hooks.registry import HookRegistry, get_registry, set_registry
    from tests.helpers.gates import make_permissive_fixture_gate

    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        sink=spy_sink,
        strict_declarations=True,
    )
    set_registry(registry)
    try:
        with pytest.raises(HookError, match="strict mode"):
            await invoke(
                "missing.declaration",
                _ctx(),
                kind="pre",
                subscribable_tiers=frozenset({"system"}),
            )
    finally:
        set_registry(prior)

    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED row for the strict-mode "
        f"undeclared arm; got {[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "missing.declaration"
    assert fields["kind"] == "pre"
    assert fields["drift_at"] == "dispatch"
    assert fields["drift_kind"] == "undeclared_hookpoint"


# ──────────────────────────────────────────────────────────────────────
# #195 — coverage of the optional invoke-time-arg fields
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enforce_drift_audit_row_omits_fail_closed_when_arg_is_none() -> None:
    """When the publisher's invoke-time ``fail_closed`` is ``None``, the
    drift audit row omits ``invoked_fail_closed`` rather than emitting
    a ``None`` placeholder.

    Closes the gap left by the existing drift tests, which all pass a
    concrete ``fail_closed=True`` / ``=False``. The per-kind dispatcher
    handlers ``_run_post`` / ``_run_error`` / ``_run_cancel`` call
    ``_enforce_subscribable_tiers`` without ``refusable_tiers`` (which
    defaults to ``None``), and a future callsite drift could pass
    ``fail_closed=None`` too. The audit-row schema treats the field as
    optional via ``if fail_closed is not None: fields[...] = ...`` —
    this test pins the omit branch so a regression to "always emit, even
    if None" surfaces as a coverage failure rather than as a stray
    ``invoked_fail_closed=None`` row.

    The test invokes the helper directly because the public ``invoke()``
    signature pins ``fail_closed: bool = False`` (defaults to ``False``,
    never ``None``); the ``None`` shape is reachable only on the
    internal helper.
    """
    # Local imports: the helper is module-internal and only exercised here.
    from alfred.hooks.invoke import _enforce_subscribable_tiers
    from alfred.hooks.registry import HookRegistry, get_registry, set_registry
    from tests.helpers.gates import make_deny_all_gate

    sink = SpyAuditSink()
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        sink=sink,
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name="fail-closed-none-drift",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T3,
    )

    # Drive _enforce_subscribable_tiers via the active registry. Save
    # the prior singleton so the test does not pollute downstream tests
    # that rely on the production singleton's state.
    prior_registry = get_registry()
    set_registry(registry)
    try:
        # Trigger subscribable_tiers drift with fail_closed=None. The
        # drift detection picks subscribable_tiers first (it's the first
        # field checked); the audit row builder then enters the
        # optional-field block where fail_closed is None.
        with pytest.raises(HookError, match="subscribable_tiers"):
            await _enforce_subscribable_tiers(
                "fail-closed-none-drift",
                _ctx(),
                kind="pre",
                subscribable_tiers=frozenset({"user-plugin"}),  # drift
                refusable_tiers=None,
                fail_closed=None,  # the None we are pinning
            )
    finally:
        set_registry(prior_registry)

    matching = [c for c in sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one drift row; got {[c['event'] for c in sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["drift_kind"] == "subscribable_tiers"
    # The load-bearing assertion for the missing-branch coverage: the
    # row OMITS invoked_fail_closed when the arg is None.
    assert "invoked_fail_closed" not in fields, (
        f"expected invoked_fail_closed to be omitted when arg is None; got fields={fields!r}"
    )
    # The optional refusable_tiers field follows the same contract.
    assert "invoked_refusable_tiers" not in fields
