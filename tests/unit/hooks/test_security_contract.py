"""Tests for ``alfred.hooks.invoke``'s §6.5 refusal-authorization arm — PR-A Task 11.

The plan pins the §6.5 contract:

* An AUTHORIZED :class:`HookRefusal` (raised by a subscriber whose
  ``tier`` is in :func:`invoke`'s ``refusable_tiers`` argument) short-
  circuits the ``pre`` chain, propagates uncaught to the caller, and is
  recorded as a :data:`alfred.hooks.audit_sink.HOOKS_REFUSAL` row.
* An UNAUTHORIZED :class:`HookRefusal` (subscriber tier NOT in
  ``refusable_tiers``) is recorded as
  :data:`alfred.hooks.audit_sink.HOOKS_UNAUTHORIZED_REFUSAL` and then
  SWALLOWED — the action body still runs with the last-good ctx. The
  audit row IS the loud-failure escape (CLAUDE.md hard rule #7);
  surfacing a :class:`HookError` to the caller for a hook the caller
  never wrote would violate the spec §6.5 "fail-loud via audit, not
  raised error" disposition.

This file pins eleven invariants:

1. Authorized refusal: tier IN ``refusable_tiers`` → :data:`HOOKS_REFUSAL` +
   re-raise.
2. Unauthorized refusal: tier NOT IN ``refusable_tiers`` →
   :data:`HOOKS_UNAUTHORIZED_REFUSAL` + NO raise + chain continues.
3. Earlier mutation discarded on authorized refusal — the chain_ctx mutated
   by subscriber A before subscriber B's authorized refusal never reaches
   the caller (because invoke raises).
4. Chain continues past unauthorized refusal with last-good ctx —
   subsequent subscribers run; the unauthorized subscriber's would-be
   mutation is discarded; earlier subscribers' mutations are preserved.
5. Default ``refusable_tiers`` is permissive — every tier can refuse by
   default (matches the spec §0 default-permit posture for refusals).
6. Refusal audit schema is closed — fields equal
   :data:`alfred.hooks.invoke._REFUSAL_AUDIT_FIELDS` set-equality.
7. No T3 leak via ``refusal.reason`` — the subscriber-supplied reason
   string is NEVER copied into audit fields.
8. Authorized-refusal row carries ``subscriber_tier``.
9. Unauthorized-refusal row carries ``subscriber_tier``.
10. Multiple refusable tiers — both system and operator subscribers can
    refuse; user-plugin refusals are still audited as unauthorized.
11. post / error / cancel HookRefusals are NOT subject to §6.5 — they
    propagate uncaught via the Task-10 defensive re-raise and emit
    NEITHER refusal event id. (Regression pin: §6.5 is pre-only.)

The tests use :class:`tests.unit.hooks.conftest.SpyAuditSink` injected
into a :class:`HookRegistry` with ``allow_system=True`` (via the shared
:func:`tests.unit.hooks.conftest.spy_registry_allow_system` fixture) so
a system-tier subscriber can be registered without tripping the dev
gate. The fixture restores the prior registry on teardown — no cross-
test contamination through the module-level singleton (CLAUDE.md
no-global-state rule).
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

import pytest

from alfred.hooks.audit_sink import (
    HOOKS_REFUSAL,
    HOOKS_SUBSCRIBER_ERROR,
    HOOKS_UNAUTHORIZED_REFUSAL,
)
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookRefusal
from alfred.hooks.invoke import _REFUSAL_AUDIT_FIELDS, invoke
from alfred.hooks.registry import HookRegistry

from .conftest import SpyAuditSink

# ──────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────


def _ctx(
    *,
    input_: object = "initial",
    hookpoint: str = "hp",
    correlation_id: str = "corr-sec",
) -> HookContext[Any]:
    """Build a fresh :class:`HookContext` for a security-contract test.

    Centralised so a future field addition does not churn every test.
    Kind defaults to ``"pre"`` because every §6.5 test exercises the
    pre handler (the regression pin for post/error/cancel passes its
    own kind explicitly).
    """
    return HookContext(
        action_id="action.test",
        hookpoint=hookpoint,
        input=input_,
        correlation_id=correlation_id,
        kind="pre",
    )


def _refusal_rows(spy_sink: SpyAuditSink) -> list[dict[str, object]]:
    """Filter the spy sink's call list to authorized-refusal rows."""
    return [c for c in spy_sink.calls if c["event"] == HOOKS_REFUSAL]


def _unauthorized_rows(spy_sink: SpyAuditSink) -> list[dict[str, object]]:
    """Filter the spy sink's call list to unauthorized-refusal rows."""
    return [c for c in spy_sink.calls if c["event"] == HOOKS_UNAUTHORIZED_REFUSAL]


def _tier_from(row: dict[str, object]) -> object:
    """Narrow ``row["fields"]`` to ``dict`` and read ``subscriber_tier``.

    mypy ``--strict`` rejects ``row["fields"]["subscriber_tier"]`` directly
    because ``dict[str, object]`` deindexes to ``object``, which is not
    indexable. Tests that only need the tier field collapse to one call
    through this helper instead of inlining the
    ``fields = row["fields"]; assert isinstance(fields, dict)`` narrowing
    every time. Returns ``object`` because the audit-row schema is
    deliberately loose at the test boundary — callers compare against a
    literal string (``"operator"``, ``"user-plugin"``, etc.) which is the
    real shape pin.
    """
    fields = row["fields"]
    assert isinstance(fields, dict)
    return fields["subscriber_tier"]


# ──────────────────────────────────────────────────────────────────────
# 1. Authorized refusal — tier IN refusable_tiers → audit + propagate
# ──────────────────────────────────────────────────────────────────────


async def test_authorized_refusal_emits_audit_then_propagates(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """An ``operator``-tier subscriber's :class:`HookRefusal` reaches the
    caller as a raised exception AND lands a :data:`HOOKS_REFUSAL` audit
    row when ``refusable_tiers`` includes ``"operator"``.

    The visible invariant is "raised AND audited" — the emission MUST
    complete before the propagate (the sink call inside the except
    handler is awaited before the bare ``raise``), so even if the caller
    fails to catch the refusal the audit row is durable.
    """

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.dlp",
            action_id="action.test",
            reason="contains-secret",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=refuser,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    with pytest.raises(HookRefusal):
        await invoke(
            "hp",
            _ctx(),
            kind="pre",
            refusable_tiers=frozenset({"operator"}),
        )

    rows = _refusal_rows(spy_sink)
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == HOOKS_REFUSAL
    assert row["correlation_id"] == "corr-sec"
    fields = row["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "hp"
    assert fields["kind"] == "pre"
    assert fields["subscriber_tier"] == "operator"
    # Unauthorized arm did NOT fire.
    assert _unauthorized_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 2. Unauthorized refusal — tier NOT IN refusable_tiers → audit + NO raise
# ──────────────────────────────────────────────────────────────────────


async def test_unauthorized_refusal_emits_audit_and_swallows(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A ``user-plugin``-tier subscriber's :class:`HookRefusal` does NOT
    reach the caller when ``refusable_tiers`` excludes ``"user-plugin"``.

    The visible invariant is "audited AND swallowed" — the audit row IS
    the loud-failure escape per §6.5 ("fail-loud via audit row, not
    raised error"), and the action body proceeds with the last-good ctx
    as if the subscriber never ran.
    """

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.user",
            action_id="action.test",
            reason="user-rule",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=refuser,
        hookpoint="hp",
        kind="pre",
        tier="user-plugin",
    )

    # refusable_tiers explicitly excludes "user-plugin" — only system
    # subscribers in this set are permitted to refuse.
    result = await invoke(
        "hp",
        _ctx(input_="payload"),
        kind="pre",
        refusable_tiers=frozenset({"system"}),
    )

    # No exception reached the caller; last-good ctx returned with the
    # original input preserved (the swallowed subscriber's would-be
    # mutation is discarded).
    assert result.input == "payload"

    rows = _unauthorized_rows(spy_sink)
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == HOOKS_UNAUTHORIZED_REFUSAL
    assert row["correlation_id"] == "corr-sec"
    fields = row["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "hp"
    assert fields["kind"] == "pre"
    assert fields["subscriber_tier"] == "user-plugin"
    # Authorized arm did NOT fire.
    assert _refusal_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 3. Earlier mutation discarded on authorized refusal
# ──────────────────────────────────────────────────────────────────────


async def test_authorized_refusal_discards_earlier_mutation(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """When subscriber A mutates ``chain_ctx`` and subscriber B raises
    an authorized :class:`HookRefusal`, the action body never observes
    A's mutation: :func:`invoke` raises before returning a ctx, so the
    caller's caught exception means there is no rewritten ctx to act on.

    Also pins that subscriber C never runs — the chain short-circuits at
    B's refusal, NOT at the end of the chain.
    """
    c_ran = False

    async def a(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("A-touched")

    async def b(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.b",
            action_id="action.test",
            reason="block",
            correlation_id="corr-sec",
        )

    async def c(ctx: HookContext[Any]) -> HookContext[Any]:
        nonlocal c_ran
        c_ran = True
        return ctx.with_metadata(reached=True)

    for fn in (a, b, c):
        spy_registry_allow_system.register(
            hook_fn=fn,
            hookpoint="hp",
            kind="pre",
            tier="operator",
        )

    with pytest.raises(HookRefusal):
        await invoke(
            "hp",
            _ctx(input_="initial"),
            kind="pre",
            refusable_tiers=frozenset({"operator"}),
        )

    # C never ran — chain short-circuited at B's refusal.
    assert c_ran is False
    # Exactly one authorized refusal row landed; B's row.
    assert len(_refusal_rows(spy_sink)) == 1


# ──────────────────────────────────────────────────────────────────────
# 4. Chain continues past unauthorized refusal with last-good ctx
# ──────────────────────────────────────────────────────────────────────


async def test_unauthorized_refusal_preserves_chain_continuity(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """Three subscribers in order — A (operator) mutates input; B
    (user-plugin) raises an UNAUTHORIZED refusal; C (operator) writes
    metadata. With ``refusable_tiers`` excluding ``"user-plugin"``:

    * B is audited as unauthorized and swallowed (no raise).
    * C still runs (chain did not short-circuit).
    * The returned ctx preserves A's mutation (B's discarded would-be
      mutation never reached C) AND carries C's metadata.
    """
    c_ran = False

    async def a(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("A-touched")

    async def b(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.user",
            action_id="action.test",
            reason="user-rule",
            correlation_id="corr-sec",
        )

    async def c(ctx: HookContext[Any]) -> HookContext[Any]:
        nonlocal c_ran
        c_ran = True
        return ctx.with_metadata(reached=True)

    spy_registry_allow_system.register(hook_fn=a, hookpoint="hp", kind="pre", tier="operator")
    spy_registry_allow_system.register(hook_fn=b, hookpoint="hp", kind="pre", tier="user-plugin")
    spy_registry_allow_system.register(hook_fn=c, hookpoint="hp", kind="pre", tier="operator")

    result = await invoke(
        "hp",
        _ctx(input_="initial"),
        kind="pre",
        refusable_tiers=frozenset({"operator", "system"}),
    )

    assert c_ran is True
    # A's mutation preserved (B's would-be mutation discarded).
    assert result.input == "A-touched"
    # C's metadata is on the returned ctx.
    assert result.metadata.get("reached") is True
    # Exactly one unauthorized row landed (B); no authorized rows.
    assert len(_unauthorized_rows(spy_sink)) == 1
    assert _refusal_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 5. Default refusable_tiers is permissive
# ──────────────────────────────────────────────────────────────────────


async def test_default_refusable_tiers_allows_user_plugin_refusal(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """Spec §0: the default ``refusable_tiers`` is the full
    ``{"system", "operator", "user-plugin"}`` set — every tier can
    refuse unless the caller narrows the set. A ``user-plugin``-tier
    subscriber's refusal must therefore propagate when :func:`invoke`
    is called WITHOUT a ``refusable_tiers`` override, and emit a
    :data:`HOOKS_REFUSAL` (not unauthorized) row.
    """

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.user",
            action_id="action.test",
            reason="user-rule",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=refuser,
        hookpoint="hp",
        kind="pre",
        tier="user-plugin",
    )

    with pytest.raises(HookRefusal):
        await invoke("hp", _ctx(), kind="pre")

    rows = _refusal_rows(spy_sink)
    assert len(rows) == 1
    assert _tier_from(rows[0]) == "user-plugin"
    assert _unauthorized_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 6. Refusal audit schema is closed
# ──────────────────────────────────────────────────────────────────────


async def test_refusal_audit_row_fields_schema(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """Pin the canonical key set on BOTH refusal events.

    A drift in the schema breaks PR-B's :class:`AuditWriter`-backed
    projector. The same constant
    (:data:`alfred.hooks.invoke._REFUSAL_AUDIT_FIELDS`) governs both
    :data:`HOOKS_REFUSAL` and :data:`HOOKS_UNAUTHORIZED_REFUSAL` rows —
    they share field shape and differ only by ``event`` value.
    """

    async def authorized_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.dlp",
            action_id="action.test",
            reason="dlp-block",
            correlation_id="corr-sec",
        )

    async def unauthorized_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.user",
            action_id="action.test",
            reason="user-rule",
            correlation_id="corr-sec",
        )

    # Authorized arm first — operator-tier, refusable.
    spy_registry_allow_system.register(
        hook_fn=authorized_refuser,
        hookpoint="hp-auth",
        kind="pre",
        tier="operator",
    )
    with pytest.raises(HookRefusal):
        await invoke(
            "hp-auth",
            _ctx(hookpoint="hp-auth"),
            kind="pre",
            refusable_tiers=frozenset({"operator"}),
        )

    # Unauthorized arm second — user-plugin tier, not refusable.
    spy_registry_allow_system.register(
        hook_fn=unauthorized_refuser,
        hookpoint="hp-unauth",
        kind="pre",
        tier="user-plugin",
    )
    await invoke(
        "hp-unauth",
        _ctx(hookpoint="hp-unauth"),
        kind="pre",
        refusable_tiers=frozenset({"system"}),
    )

    auth_rows = _refusal_rows(spy_sink)
    unauth_rows = _unauthorized_rows(spy_sink)
    assert len(auth_rows) == 1
    assert len(unauth_rows) == 1

    # Both rows MUST use the canonical schema verbatim.
    for row in (auth_rows[0], unauth_rows[0]):
        fields = row["fields"]
        assert isinstance(fields, dict)
        assert set(fields.keys()) == _REFUSAL_AUDIT_FIELDS


# ──────────────────────────────────────────────────────────────────────
# 7. No T3 leak via refusal.reason
# ──────────────────────────────────────────────────────────────────────


async def test_refusal_reason_does_not_leak_into_audit_fields(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """CLAUDE.md hard rule #1 — never log secrets. The subscriber-
    supplied ``reason`` may carry T3 user content (e.g. a quoted
    fragment of the rejected input). The audit ``fields`` mapping MUST
    NOT include that string for EITHER refusal event. The propagating
    exception's ``str()`` DOES carry the reason — that's the operator's
    visibility surface — but the durable audit row deliberately omits
    it to keep the row schema closed AND secret-leak free.
    """
    # Synthetic shape used to prove the audit row never copies a
    # subscriber-supplied ``refusal.reason`` into ``fields``. Not a real
    # credential; ruff's S105 hardcoded-password heuristic fires on the
    # ``sk-`` prefix.
    secret_shaped = "sk-LIVE-deadbeef-secret-shape"  # noqa: S105

    async def auth_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.auth",
            action_id="action.test",
            reason=secret_shaped,
            correlation_id="corr-sec",
        )

    async def unauth_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.unauth",
            action_id="action.test",
            reason=secret_shaped,
            correlation_id="corr-sec",
        )

    # Authorized run.
    spy_registry_allow_system.register(
        hook_fn=auth_refuser, hookpoint="hp-auth", kind="pre", tier="operator"
    )
    with pytest.raises(HookRefusal):
        await invoke(
            "hp-auth",
            _ctx(hookpoint="hp-auth"),
            kind="pre",
            refusable_tiers=frozenset({"operator"}),
        )

    # Unauthorized run.
    spy_registry_allow_system.register(
        hook_fn=unauth_refuser, hookpoint="hp-unauth", kind="pre", tier="user-plugin"
    )
    await invoke(
        "hp-unauth",
        _ctx(hookpoint="hp-unauth"),
        kind="pre",
        refusable_tiers=frozenset({"system"}),
    )

    # Neither row's field values may contain the secret-shaped reason.
    for row in spy_sink.calls:
        fields = row["fields"]
        assert isinstance(fields, dict)
        for value in fields.values():
            assert secret_shaped not in str(value)


# ──────────────────────────────────────────────────────────────────────
# 8. Authorized refusal row carries subscriber_tier
# ──────────────────────────────────────────────────────────────────────


async def test_authorized_refusal_row_carries_subscriber_tier(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """The authorized-refusal row's ``subscriber_tier`` field equals the
    refusing subscriber's tier (here: ``"system"``). Lets the operator
    distinguish a DLP refusal (system tier) from a persona refusal
    (operator tier) when grepping the audit log.
    """

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.system",
            action_id="action.test",
            reason="system-rule",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(hook_fn=refuser, hookpoint="hp", kind="pre", tier="system")

    with pytest.raises(HookRefusal):
        await invoke(
            "hp",
            _ctx(),
            kind="pre",
            refusable_tiers=frozenset({"system"}),
        )

    rows = _refusal_rows(spy_sink)
    assert len(rows) == 1
    assert _tier_from(rows[0]) == "system"


# ──────────────────────────────────────────────────────────────────────
# 9. Unauthorized refusal row carries subscriber_tier
# ──────────────────────────────────────────────────────────────────────


async def test_unauthorized_refusal_row_carries_subscriber_tier(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """The unauthorized-refusal row's ``subscriber_tier`` field equals
    the refusing subscriber's tier (here: ``"user-plugin"``). Lets the
    operator see which untrusted plugin attempted an unauthorized
    refusal — load-bearing attribution for the post-incident report
    when a sandbox-escape attempt fires this arm.
    """

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.user",
            action_id="action.test",
            reason="user-rule",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=refuser, hookpoint="hp", kind="pre", tier="user-plugin"
    )

    await invoke(
        "hp",
        _ctx(),
        kind="pre",
        refusable_tiers=frozenset({"operator"}),
    )

    rows = _unauthorized_rows(spy_sink)
    assert len(rows) == 1
    assert _tier_from(rows[0]) == "user-plugin"


# ──────────────────────────────────────────────────────────────────────
# 10. Multiple refusable tiers — system AND operator can refuse
# ──────────────────────────────────────────────────────────────────────


async def test_multiple_refusable_tiers(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A ``refusable_tiers`` set with more than one tier accepts refusals
    from EACH listed tier, and audits refusals from any other tier as
    unauthorized. Pins that the dispatcher does NOT collapse the set to
    a single tier internally — every element is honoured.

    Setup: three hookpoints; one ``system`` refuser, one ``operator``
    refuser, one ``user-plugin`` refuser. ``refusable_tiers`` is
    ``{"system", "operator"}``. Expectations:

    * system + operator subscribers propagate (authorized).
    * user-plugin subscriber is swallowed (unauthorized).
    """

    def make_refuser(
        hook_id: str,
    ) -> Callable[[HookContext[Any]], Coroutine[Any, Any, HookContext[Any] | None]]:
        async def _refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
            raise HookRefusal(
                hook_id=hook_id,
                action_id="action.test",
                reason="refuse",
                correlation_id="corr-sec",
            )

        return _refuser

    sys_fn = make_refuser("hook.sys")
    op_fn = make_refuser("hook.op")
    up_fn = make_refuser("hook.up")

    spy_registry_allow_system.register(
        hook_fn=sys_fn, hookpoint="hp-sys", kind="pre", tier="system"
    )
    spy_registry_allow_system.register(
        hook_fn=op_fn, hookpoint="hp-op", kind="pre", tier="operator"
    )
    spy_registry_allow_system.register(
        hook_fn=up_fn, hookpoint="hp-up", kind="pre", tier="user-plugin"
    )

    refusable = frozenset({"system", "operator"})

    with pytest.raises(HookRefusal):
        await invoke("hp-sys", _ctx(hookpoint="hp-sys"), kind="pre", refusable_tiers=refusable)
    with pytest.raises(HookRefusal):
        await invoke("hp-op", _ctx(hookpoint="hp-op"), kind="pre", refusable_tiers=refusable)
    # user-plugin: NO raise — audited as unauthorized.
    await invoke("hp-up", _ctx(hookpoint="hp-up"), kind="pre", refusable_tiers=refusable)

    auth_rows = _refusal_rows(spy_sink)
    unauth_rows = _unauthorized_rows(spy_sink)

    def _tiers(rows: list[dict[str, object]]) -> set[object]:
        out: set[object] = set()
        for row in rows:
            fields = row["fields"]
            assert isinstance(fields, dict)
            out.add(fields["subscriber_tier"])
        return out

    assert _tiers(auth_rows) == {"system", "operator"}
    assert _tiers(unauth_rows) == {"user-plugin"}


# ──────────────────────────────────────────────────────────────────────
# 11. §6.5 is pre-only — post/error/cancel HookRefusals propagate naively
# ──────────────────────────────────────────────────────────────────────


async def test_post_refusal_is_not_subject_to_section_65(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A :class:`HookRefusal` raised by a ``post`` subscriber propagates
    uncaught (Task-10 defensive re-raise) — it is NEITHER audited as
    authorized nor unauthorized, NOR wrapped as a subscriber error.

    The §6.5 contract is meaningful only for the ``pre`` chain, which
    has a "deny the action" semantic. Refusals at post/error/cancel
    times are subscriber-author errors (the action ran already / failed
    already / was cancelled already; refusing makes no sense) and so the
    dispatcher does not silently audit them; the propagating exception
    is the loud-failure signal. Regression pin against accidentally
    layering refusal-authorization onto the wrong arm.
    """

    async def post_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.post",
            action_id="action.test",
            reason="post-refuse",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=post_refuser, hookpoint="hp", kind="post", tier="user-plugin"
    )

    # Even with refusable_tiers={"system"} (would be unauthorized for
    # this user-plugin subscriber if §6.5 applied), the refusal MUST
    # still propagate from the post chain.
    with pytest.raises(HookRefusal):
        await invoke(
            "hp",
            _ctx(),
            kind="post",
            refusable_tiers=frozenset({"system"}),
        )

    # NEITHER refusal event fired on the post arm.
    assert _refusal_rows(spy_sink) == []
    assert _unauthorized_rows(spy_sink) == []
    # And the post-arm refusal is NOT mis-attributed as a subscriber error.
    sub_err_rows = [c for c in spy_sink.calls if c["event"] == HOOKS_SUBSCRIBER_ERROR]
    assert sub_err_rows == []


async def test_error_refusal_is_not_subject_to_section_65(
    spy_registry_allow_system: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """Same regression pin for the ``error`` chain. The Task-10 defensive
    re-raise of :class:`HookRefusal` propagates the exception uncaught,
    REPLACING the upstream exception the error stage would otherwise
    re-raise. Neither refusal event fires.
    """

    async def error_refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="hook.err",
            action_id="action.test",
            reason="err-refuse",
            correlation_id="corr-sec",
        )

    spy_registry_allow_system.register(
        hook_fn=error_refuser, hookpoint="hp", kind="error", tier="user-plugin"
    )

    with pytest.raises(HookRefusal):
        await invoke(
            "hp",
            _ctx(),
            kind="error",
            exc=RuntimeError("upstream"),
            refusable_tiers=frozenset({"system"}),
        )

    assert _refusal_rows(spy_sink) == []
    assert _unauthorized_rows(spy_sink) == []
    sub_err_rows = [c for c in spy_sink.calls if c["event"] == HOOKS_SUBSCRIBER_ERROR]
    assert sub_err_rows == []
