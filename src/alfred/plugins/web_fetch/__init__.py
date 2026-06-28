"""web.fetch host-side package (spec §7).

This package owns the host-side primitives the ``alfred-web-fetch``
plugin relies on:

* :mod:`alfred.plugins.web_fetch.errors` — operational error tree
  (:class:`WebFetchError`) + security event (:class:`WebFetchCanaryTripped`).
* :mod:`alfred.plugins.web_fetch.content_store` — Redis-backed
  :class:`ContentStore` with single-use ``GETDEL`` semantics.
* :mod:`alfred.plugins.web_fetch.allowlist` — three-way
  ``manifest ∩ operator ∩ session`` intersection.
* :mod:`alfred.plugins.web_fetch.rate_limit` — Lua-atomic three-bucket
  sliding-window :class:`RateLimiter`.
* :mod:`alfred.plugins.web_fetch.canary_scanner` —
  :class:`InboundCanaryScanner` (system-tier hook subscriber).

This module exports the public surface via :data:`__all__` and ships
:func:`register_hookpoints` — the one-shot bootstrap call that declares
``tool.web.fetch`` with system-only tier policy (spec §7.5 / §14).
Callers (the plugin-host bootstrap) call it once at startup; the
underlying :meth:`HookRegistry.register_hookpoint` is idempotent on
equal metadata so module re-imports under test isolation do not raise.
"""

from __future__ import annotations

from alfred.hooks import SYSTEM_ONLY_TIERS, HookRegistry
from alfred.plugins.web_fetch.allowlist import (
    AllowlistEntry,
    AllowlistIntersection,
    BroadeningCapEvent,
    DomainNotAllowed,
)
from alfred.plugins.web_fetch.canary_scanner import (
    SCANNER_HOOKPOINT,
    SCANNER_KIND,
    SCANNER_TIER,
    CanaryScanError,
    CanaryToken,
    InboundCanaryScanner,
)
from alfred.plugins.web_fetch.content_store import (
    ContentHandle,
    ContentHandleExpired,
    ContentStore,
)
from alfred.plugins.web_fetch.errors import (
    WebFetchCanaryTripped,
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.plugins.web_fetch.rate_limit import RateLimitConfig, RateLimiter
from alfred.security.tiers import T3


def register_hookpoints(registry: HookRegistry) -> None:
    """Declare the ``tool.web.fetch`` hookpoint with system-only tier
    policy (spec §7.5, §14).

    Called once at plugin-host bootstrap. The underlying
    :meth:`HookRegistry.register_hookpoint` is idempotent on equal
    metadata, so a second call (e.g. from a test fixture that re-imports
    the publisher module) does not raise.

    Tier policy:

    * ``subscribable_tiers = SYSTEM_ONLY_TIERS`` — only system-tier
      components may subscribe. The canary scanner (Task 5) is the
      legitimate subscriber. An operator or user-plugin subscriber
      could silently observe T3 ingress; the system-only restriction
      defends against that.
    * ``refusable_tiers = SYSTEM_ONLY_TIERS`` — only system-tier
      components may refuse the fetch. Operator-tier refusals on a
      post-fetch chain would be a footgun (the fetch already
      happened); user-plugin refusals would let plugins quietly drop
      results other plugins issued.
    * ``fail_closed = True`` — a subscriber timeout or unexpected
      exception fails the chain. A system-tier security observer that
      goes silent MUST NOT be ignored; fail-closed surfaces the fault
      via a ``tool.web.fetch`` ``result='fault'`` audit row.

    Args:
        registry: The process-singleton :class:`HookRegistry`. Pass
            ``alfred.hooks.get_registry()`` in production; tests pass
            the per-test fixture registry.
    """
    registry.register_hookpoint(
        name="tool.web.fetch",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        refusable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
        # PR-S4-3: T3 carrier — web fetch returns T3 (untrusted external) content.
        carrier_tier=T3,
    )


__all__ = [
    "SCANNER_HOOKPOINT",
    "SCANNER_KIND",
    "SCANNER_TIER",
    "AllowlistEntry",
    "AllowlistIntersection",
    "BroadeningCapEvent",
    "CanaryScanError",
    "CanaryToken",
    "ContentHandle",
    "ContentHandleExpired",
    "ContentStore",
    "DomainNotAllowed",
    "InboundCanaryScanner",
    "RateLimitConfig",
    "RateLimiter",
    "WebFetchCanaryTripped",
    "WebFetchDomainNotAllowed",
    "WebFetchError",
    "WebFetchRateLimited",
    "register_hookpoints",
]
