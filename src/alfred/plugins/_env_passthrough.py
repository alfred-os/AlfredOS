"""Whitelisted parent-env passthrough for the plugin subprocess (arch-003 fix).

The plugin subprocess inherits a **minimal env** (spec §5.3 / sec-011):
``PATH``, ``LANG``, ``LC_ALL``, and an opt-in ``ALFRED_PROVIDER_KEY_FD``
when a provider key is being delivered. The host process's own
``os.environ`` is NEVER inherited — an AST guard in
``tests/unit/plugins/test_env_scrub_subprocess.py`` enforces that
``stdio_transport.py`` cannot read any host-env surface (``os.environ``,
``os.environb``, ``os.getenv``, ``os.getenvb``, or any ``from os import
environ`` rebind).

That guard is load-bearing, but it created a regression: the documented
dev-mode TLS escape hatch (spec §7.11, ``TlsPolicy.__post_init__``) reads
``ALFRED_ENV`` from the subprocess's environment. With the subprocess
running under the minimal env, ``ALFRED_ENV`` is **always unset** in the
child, so the policy defaults to ``"production"`` and refuses
``skip_tls_verify=True`` even when the operator legitimately set
``ALFRED_ENV=development`` on the parent. The escape hatch never fires.
arch-003 (HIGH) flagged this.

**Fix shape.** This module is the **sole sanctioned reader** of the
parent-side ``ALFRED_ENV`` for the plugin-subprocess passthrough. It
exposes :func:`alfred_env_for_subprocess`, which returns the operator's
parent-side value (defaulting to ``"production"`` when unset). The
transport imports the function and threads the single value into the
minimal-env dict it builds before ``create_subprocess_exec``. The AST
guard against host-env reads in ``stdio_transport.py`` stays intact;
``ALFRED_ENV`` is the **only** parent-env key that crosses the boundary,
and the crossing happens here in a file the guard does not cover.

**Why a separate module rather than inline.** Three reasons:

1. The AST guard in ``test_env_scrub_subprocess.py`` walks
   ``stdio_transport.py`` only. Pulling the env read into a tiny helper
   module preserves the guard without weakening its catch surface —
   future contributors still cannot reintroduce ``os.environ`` in the
   transport itself.
2. ``ALFRED_ENV`` is **whitelisted on purpose**: it's the documented dev
   escape hatch, it carries no secret material, and the broader
   ``tests/unit/security/test_no_direct_env_reads.py`` guard only fires
   on ``ALFRED_<SUPPORTED_SECRET>`` keys (broker domain) — ``ALFRED_ENV``
   is outside that set. Centralising the read in one module keeps the
   whitelist auditable (one ``grep`` site).
3. The bootstrap factory at :mod:`alfred.bootstrap.gate_factory` already
   establishes the precedent for sanctioned ``ALFRED_ENV`` reads in
   ``src/alfred/``; this module mirrors that pattern for the
   plugin-subprocess boundary.

**Non-goals.** This module deliberately does **NOT** expose a generic
"passthrough this env key" surface. ``ALFRED_ENV`` is the only key the
plugin sandbox needs from the parent. Any future passthrough proposal
requires an ADR — silently widening the inherited surface defeats the
whole sec-011 / spec §5.3 invariant.
"""

from __future__ import annotations

import os
from typing import Final

# The single env key this module is sanctioned to read. Bound at module
# scope so the literal appears exactly once — adding a second sanctioned
# key requires an explicit edit here and an ADR, not a drive-by.
_ENV_KEY: Final[str] = "ALFRED_ENV"

# The fail-closed default. When the operator has not set ``ALFRED_ENV``
# on the parent, the subprocess sees ``"production"``, which is the
# correct posture for the TLS-policy fail-closed contract.
_DEFAULT: Final[str] = "production"


def alfred_env_for_subprocess() -> str:
    """Return the parent's ``ALFRED_ENV`` (defaulting to ``"production"``).

    Reads ``ALFRED_ENV`` from the host process's environment, defaulting
    to ``"production"`` when unset, empty, or whitespace-only. The latter
    two cases match :func:`alfred.bootstrap.gate_factory.is_production`'s
    treatment — an exported-but-empty variable is a common shell-config
    foot-gun and should not silently flip a security-relevant flag to a
    weaker setting.

    The plugin subprocess then sees the resolved value in its env, and
    :class:`alfred.plugins.web_fetch.tls_policy.TlsPolicy` honours the
    operator's intent: ``ALFRED_ENV=development`` permits the
    ``skip_tls_verify`` escape hatch; anything else refuses it.

    This is the single sanctioned passthrough path. The transport must
    NEVER read ``os.environ`` directly (the AST guard enforces that);
    instead it imports this function and substitutes the returned value
    into the minimal-env dict before ``create_subprocess_exec``.
    """
    # ``os.environ.get(_ENV_KEY, "").strip()`` mirrors gate_factory's
    # treatment of empty / whitespace as "missing" so the operator-error
    # mode (``export ALFRED_ENV=``) does not inadvertently weaken the
    # subprocess-side TLS check.
    value = os.environ.get(_ENV_KEY, "").strip()
    return value if value else _DEFAULT


__all__ = ["alfred_env_for_subprocess"]
