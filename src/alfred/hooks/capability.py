"""Hook subsystem capability gate Protocol — spec §0 / §6.2 / §6.3.

The capability gate is the load-bearing security seam between a hook
subscriber's *requested* trust tier and the runtime's *granted* trust
tier. Every action that runs a hook chain consults a gate before
dispatch; a denial is a refusal-at-the-boundary, not a downstream check.

This module exposes the structural seam every gate implementation
honours:

* :class:`CapabilityGate` — a ``@runtime_checkable`` :class:`typing.Protocol`
  describing the three methods (``check``, ``check_plugin_load``,
  ``check_content_clearance``) every gate implementation must offer.
  Dispatcher code (``_run_chain`` and friends) type-narrows against this
  Protocol; concrete gates do not need to subclass anything.

Implementation history:

* Slice 2.5 shipped :class:`DevGate` here as a dev-time default that
  ignored ``plugin_id`` / ``hookpoint`` and returned predictable
  answers without consulting an external store. The PR-S3-2 work
  introduced :class:`alfred.security.capability_gate._gate.RealGate`
  as the production implementation, and PR-S3-7 (this flag-day)
  removed :class:`DevGate` from ``src/`` entirely — see git history
  for the Slice-2.5 implementation. Production code now wires
  :class:`RealGate` exclusively (via
  :mod:`alfred.bootstrap.gate_factory`); the test suite uses
  :mod:`tests.helpers.gates` to construct deny-path / granted-path
  fixtures over :class:`RealGate` with an in-memory stub backend.

Hard-rule invariants:

* **CLAUDE.md hard rule #4** — never bypass the capability layer.
  Every PRODUCTION gate implementation (today: :class:`RealGate` and
  any future operator-grant gate consulting a different store) MUST
  consult its grant table via
  :class:`alfred.security.capability_gate.policy.GrantRow`; no shortcut
  return.

  **Bootstrap-sentinel carve-out:** the module-level
  :class:`alfred.hooks.registry._DenyAllGate` is a legitimate
  :class:`CapabilityGate` implementation that satisfies hard rule #4 by
  *unconditionally* denying — it is the fail-closed lazy default for
  any ``@hook`` decorator that registers before
  :mod:`alfred.bootstrap.gate_factory` installs :class:`RealGate` via
  :func:`alfred.hooks.set_registry`. Because every call returns
  ``False`` regardless of inputs, no bypass is possible; the rule's
  intent (no shortcut to *grant*) is preserved. See
  ``docs/glossary.md#_denyallgate`` for the lazy-default boundary spec.

* **CLAUDE.md hard rule #7** — no silent failures. An unknown / typo'd /
  case-mismatched tier denies fail-closed — the production
  :class:`RealGate` rejects via the closed-domain check in
  :class:`alfred.security.capability_gate.policy.GrantRow`; the
  bootstrap sentinel :class:`_DenyAllGate` rejects unconditionally.
* **sec-007 (no env reads)** — this module imports nothing from
  :mod:`os` (no ``import os``, no ``os.environ`` / ``os.getenv``).
  ``ALFRED_ENV`` selection lives in :mod:`alfred.bootstrap.gate_factory`;
  the AST-scan regression guard in
  ``tests/unit/hooks/test_capability_sec007.py`` keeps the env-read
  out of this file.

Forward-compat: any future gate implementation (e.g. an
operator-grant gate consulting a different store) sits behind the same
:class:`CapabilityGate` Protocol. The Protocol's signature is the
public contract every implementation must honour — ``plugin_id`` and
``hookpoint`` are part of that contract on every method that takes a
subscriber-side coordinate.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CapabilityGate(Protocol):
    """Structural Protocol every capability gate implementation honours.

    A gate's only job is to answer *yes-or-no* for a tier request from
    a given plugin at a given hookpoint. The Protocol is
    ``@runtime_checkable`` so dispatcher code can type-narrow with
    :func:`isinstance` — the production :class:`RealGate` and test
    fixture gates (in :mod:`tests.helpers.gates`) all satisfy this
    structural seam without sharing a concrete base class.

    The keyword-only signature is part of the public contract: a caller
    cannot accidentally swap ``plugin_id`` and ``hookpoint`` via
    positional args. Every gate implementation MUST preserve the
    ``*,`` discipline on every method.
    """

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool: ...

    def check_plugin_load(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
    ) -> bool:
        """Gate plugin load at handshake time.

        Called by :class:`alfred.plugins.session.AlfredPluginSession`
        (PR-S3-3a) before the plugin's stdio transport opens. A refusal
        emits ``plugin.lifecycle.load_refused`` and the supervisor marks
        the plugin REFUSED until re-granted (spec §8.2).

        ``manifest_tier`` is the subscriber-capability axis the plugin's
        manifest declares (``"system"`` / ``"operator"`` / ``"user-plugin"``);
        it is ORTHOGONAL to the content trust tier (T0-T3). The two axes
        share no codomain — they are checked separately.
        """
        ...

    def check_content_clearance(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        content_tier: str,
    ) -> bool:
        """Gate content-tier access on the orthogonal trust axis.

        Spec §8.2 (Fork 7): T3 content must not reach T2-only paths. The
        quarantined-LLM plugin host and the StdioTransport boundary are
        the only authorised callers for ``content_tier="T3"``. Every
        other caller receives ``False`` from the production
        :class:`alfred.security.capability_gate._gate.RealGate`.

        ``content_tier`` is the T0-T3 content axis; ``plugin_id`` and
        ``hookpoint`` are the subscriber-side coordinates. The gate
        consults all three.
        """
        ...
