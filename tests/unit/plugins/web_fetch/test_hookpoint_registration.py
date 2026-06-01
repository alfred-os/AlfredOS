"""``tool.web.fetch`` hookpoint registration tests (spec §7.5, §14).

The hookpoint owns the post-fetch chain — the canary scanner runs as a
system-tier ``post`` subscriber. Per spec §7.5 the hookpoint is
``SYSTEM_ONLY_TIERS`` for both subscribable and refusable: only
system-tier components may subscribe; only system-tier components may
refuse. Operator and user-plugin subscribers are refused at
registration time.

``fail_closed=True`` so a subscriber timeout or unexpected exception
fails the chain — a system-tier security observer that goes silent
must NOT be ignored.
"""

from __future__ import annotations

import pytest

from alfred.hooks import SYSTEM_ONLY_TIERS, HookError, HookRegistry
from alfred.hooks.context import HookContext
from alfred.plugins.web_fetch import register_hookpoints


def test_tool_web_fetch_hookpoint_registered(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """``register_hookpoints`` declares ``tool.web.fetch`` with
    ``SYSTEM_ONLY_TIERS`` for both subscribable and refusable,
    ``fail_closed=True``."""
    register_hookpoints(fresh_registry_allow_system)
    meta = fresh_registry_allow_system.hookpoint_meta("tool.web.fetch")
    assert meta is not None
    assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS
    assert meta.refusable_tiers == SYSTEM_ONLY_TIERS
    assert meta.fail_closed is True


def test_register_hookpoints_is_idempotent(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """Calling ``register_hookpoints`` twice with the same registry must
    not raise — the underlying ``register_hookpoint`` is idempotent on
    equal metadata.
    """
    register_hookpoints(fresh_registry_allow_system)
    register_hookpoints(fresh_registry_allow_system)  # second call: no-op
    meta = fresh_registry_allow_system.hookpoint_meta("tool.web.fetch")
    assert meta is not None


def test_operator_tier_subscriber_refused(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """Operator-tier subscribers must be refused at registration time
    (spec §7.5). The tool.web.fetch chain is system-tier observers only;
    an operator subscriber could silently observe T3 bytes the operator
    is not authorised to see.
    """
    register_hookpoints(fresh_registry_allow_system)

    async def operator_subscriber(ctx: HookContext[object]) -> None:
        return None

    with pytest.raises(HookError):
        fresh_registry_allow_system.register(
            hook_fn=operator_subscriber,
            hookpoint="tool.web.fetch",
            kind="post",
            tier="operator",
        )


def test_user_plugin_tier_subscriber_refused(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """User-plugin tier subscribers are also refused — same reason as
    operator. A canary scanner running as a user-plugin subscriber would
    let plugin authors silently observe T3 ingress."""
    register_hookpoints(fresh_registry_allow_system)

    async def user_plugin_subscriber(ctx: HookContext[object]) -> None:
        return None

    with pytest.raises(HookError):
        fresh_registry_allow_system.register(
            hook_fn=user_plugin_subscriber,
            hookpoint="tool.web.fetch",
            kind="post",
            tier="user-plugin",
        )


def test_system_tier_subscriber_accepted(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """System-tier subscribers are accepted — this is the legitimate
    canary-scanner registration path."""
    register_hookpoints(fresh_registry_allow_system)

    async def system_subscriber(ctx: HookContext[object]) -> None:
        return None

    # Must NOT raise.
    fresh_registry_allow_system.register(
        hook_fn=system_subscriber,
        hookpoint="tool.web.fetch",
        kind="post",
        tier="system",
    )
