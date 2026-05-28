"""Hook subsystem capability gate — see spec §0 and §6.2/§6.3.

The capability gate is the load-bearing security seam between a hook
subscriber's *requested* trust tier and the runtime's *granted* trust
tier. Every action that runs a hook chain consults a gate before
dispatch; a denial is a refusal-at-the-boundary, not a downstream check.

Two pieces ship this slice:

* :class:`CapabilityGate` — a ``@runtime_checkable`` :class:`typing.Protocol`
  describing the single seam every gate implementation honours. Dispatcher
  code in PR-B (Task-10's ``_run_chain``) type-narrows against this
  Protocol; concrete gates do not need to subclass anything.
* :class:`DevGate` — the dev-time default. Returns predictable answers
  without persisting state, without reading the environment, and without
  any external lookup. Slice 3 introduces the real operator-grant gate
  backed by the policy store; until then, ``DevGate`` is what the
  dispatcher constructs in test fixtures and local stack defaults.

Hard-rule invariants pinned by ``tests/unit/hooks/test_capability.py``:

* **CLAUDE.md hard rule #4** — never bypass the capability layer.
  ``DevGate`` is the real gate the tests assert against; the deny paths
  return ``False`` from a concrete refusal, not from a stub.
* **CLAUDE.md hard rule #7** — no silent failures. An unknown / typo'd /
  case-mismatched tier denies fail-closed. Empty string, alternate-case
  variants of known tiers (``"SYSTEM"``), and unknown names (``"root"``)
  all return ``False`` even with ``allow_system=True``.
* **sec-007 (no env flag)** — ``allow_system`` is constructor-only. This
  module imports nothing from :mod:`os` (no ``import os``, no
  ``os.environ`` / ``os.getenv``). Task-4 lands an AST-scan regression
  guard against any future re-introduction of an env-read here.

Forward-compat (Slice 3): the operator-grant gate will sit behind the
same :class:`CapabilityGate` Protocol. The Protocol's signature is the
public contract every future gate must honour — ``plugin_id`` and
``hookpoint`` are part of that contract even though ``DevGate`` does
not consult them this slice. A Slice-3 grant gate consults all three.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# The three tier strings the dev gate recognises. Kept as a module-level
# constant rather than an enum so the test's parametrize over unknown /
# typo'd / case-mismatched strings stays direct (`"SYSTEM"`, `""`,
# `"root"`, `"None"`) — and so a Slice-3 grant gate can introspect the
# dev-time grant table without importing an enum from this module.
_TIERS_GRANTED_UNCONDITIONALLY: frozenset[str] = frozenset({"operator", "user-plugin"})
_TIER_GATED_BY_ALLOW_SYSTEM = "system"


@runtime_checkable
class CapabilityGate(Protocol):
    """Structural Protocol every capability gate implementation honours.

    A gate's only job is to answer *yes-or-no* for a tier request from
    a given plugin at a given hookpoint. The Protocol is
    ``@runtime_checkable`` so dispatcher code can type-narrow with
    :func:`isinstance` — Slice-3's grant gate, Slice-2.5's
    :class:`DevGate`, and test fixture gates all satisfy this structural
    seam without sharing a concrete base class.

    The keyword-only signature is part of the public contract: a caller
    cannot accidentally swap ``plugin_id`` and ``hookpoint`` via
    positional args. Every gate implementation MUST preserve the
    ``*,`` discipline on :meth:`check`.
    """

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class DevGate:
    """Dev-time default :class:`CapabilityGate` implementation.

    Returns predictable answers without persisting state, reading the
    environment, or consulting an external store. The grant table is:

    * ``operator`` — always granted.
    * ``user-plugin`` — always granted.
    * ``system`` — granted iff the constructor was passed
      ``allow_system=True``.
    * anything else — denied (fail-closed on unknown / typo'd input).

    The ``plugin_id`` and ``hookpoint`` parameters are part of the
    Protocol contract but are not consulted by the dev-time gate.
    Slice-3's operator-grant gate consults all three.

    The ``allow_system`` attribute is constructor-set on a
    ``frozen=True, slots=True, kw_only=True`` dataclass — this is the
    sec-007 "constructor-only" pin at the language level. Mirrors the
    style of :class:`alfred.hooks.context.HookContext` and
    :class:`alfred.hooks.registry.Subscriber` (the other two
    frozen-slots carriers in this subsystem). Frozen prevents
    ``setattr(devgate, "allow_system", True)`` from bypassing the gate
    at runtime, so the attribute is PUBLIC (no underscore) — privacy is
    no longer load-bearing for the security contract because mutation
    is impossible.

    sec-007 forbids reading the environment here; Task-4's AST-scan
    regression guard backs the source-level pin. ``kw_only=True`` keeps
    the verbatim spec §0 signature
    ``DevGate(*, allow_system: bool = False)``: dataclass generates the
    same keyword-only constructor a hand-rolled ``__init__`` produced.
    """

    allow_system: bool = False

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool:
        """Answer yes-or-no for a tier request.

        See class docstring for the grant table. The ``plugin_id`` and
        ``hookpoint`` parameters are accepted (per the
        :class:`CapabilityGate` contract) but unused this slice.
        """
        del plugin_id, hookpoint  # Part of the Protocol contract; unused here.
        if requested_tier in _TIERS_GRANTED_UNCONDITIONALLY:
            return True
        if requested_tier == _TIER_GATED_BY_ALLOW_SYSTEM:
            return self.allow_system
        return False
