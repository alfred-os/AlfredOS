"""Shared fixtures for ``tests/unit/hooks/`` — Slice-2.5 PR-A Task 6.

These fixtures are the test-side bookend of the :class:`HookRegistry`'s
gate-and-sink injection seams (spec §0 + the alfred-core-engineer-1
hardening). Every PR-A and PR-B test that exercises the registry consumes
one of them — never instantiating a registry by hand at test scope —
because the registry is the module-level singleton seam and per-test
isolation is enforced by :func:`alfred.hooks.registry.set_registry` /
:func:`get_registry` swap-and-restore, NOT by a fresh module import.

Four fixtures ship:

* :func:`fresh_registry` — the canonical default. Installs a brand-new
  :class:`HookRegistry` with the fixture-parity gate constructed via
  :func:`tests.helpers.gates.make_default_test_gate` (operator and
  user-plugin granted, system denied — matching the Slice-2.5
  ``DevGate()`` semantics) and the registry's own default
  :class:`StructlogAuditSink`. The pre-test registry is captured at
  fixture entry and restored on teardown so cross-test contamination
  via the module-level singleton is impossible.
* :func:`fresh_registry_allow_system` — same shape, but the gate
  grants the ``system`` tier as well via
  :func:`tests.helpers.gates.make_default_test_gate` with
  ``allow_system=True``. Used by tests that need to register a
  system-tier subscriber (Task 7's @hook decorator unit tests, Task 9's
  chain-deadline tests).
* :func:`spy_registry_allow_system` — the spy-sink composition of
  ``fresh_registry_allow_system``. Installs a :class:`HookRegistry`
  with a granted-system fixture-parity gate AND a
  :class:`SpyAuditSink` injected via constructor, so fault-path audit
  rows land on the test-visible recorder rather than the global
  structlog sink. Used by Task 11's §6.5 refusal-authorization tests
  and Task 12's reentry-bypass tests against system-tier subscribers
  — the only fixture combination that needs both axes (system
  permitted + sink observable).
* :func:`spy_sink` — a structural :class:`AuditSink` test double that
  records every ``emit(event, correlation_id, fields)`` into a flat
  list. Tasks 9-12 inject this into a :class:`HookRegistry` to assert the
  fault-path audit rows (`hooks.refusal`, `hooks.chain_timeout`,
  `hooks.subscriber_error`, `hooks.unauthorized_refusal`,
  `hooks.reentry_bypass`) without depending on global structlog state.

PR-S3-7 (spec §15.1 flag-day): the gate-construction calls migrated
from the Slice-2.5 ``DevGate(...)`` constructions to
:mod:`tests.helpers.gates` factories. Tests that need the strict
production :class:`RealGate` semantics (empty grants ⇒ deny everything
including operator, exact ``plugin_id`` match) construct
:func:`tests.helpers.gates.make_deny_all_gate` /
:func:`tests.helpers.gates.make_allow_system_gate` directly; the
fixtures here use :func:`tests.helpers.gates.make_default_test_gate`
to preserve the Slice-2.5 ergonomic shape for the test bodies that
register an ``operator``-tier subscriber under an arbitrary
module-named ``plugin_id``.

The spy is a ``frozen=True, slots=True`` dataclass — same hot-path
discipline as the real :class:`StructlogAuditSink`. The ``calls`` list
itself is mutable (the recorder needs to append), but the dataclass
holds a stable reference; reassigning the list is rejected by
``FrozenInstanceError``.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

import pytest

from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from tests.helpers.gates import make_default_test_gate


@dataclass(frozen=True, slots=True)
class SpyAuditSink:
    """Structural :class:`alfred.hooks.audit_sink.AuditSink` test double.

    Records every ``emit(event, correlation_id, fields)`` call into the
    :attr:`calls` list. Frozen + slots so the spy honours the same
    "constructor-only configuration" discipline as the real sink — the
    test double cannot drift away from the production type's contract.

    The ``calls`` list is captured by reference so a test that received
    the spy via fixture continues to see every subsequent emit. The
    defensive copy of ``fields`` (``dict(fields)``) is load-bearing: a
    caller that mutates the original mapping after the emit must not
    see the recorded snapshot move.
    """

    calls: list[dict[str, object]] = field(default_factory=list)

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        """Record one entry per call. Same keyword-only seam as
        :meth:`alfred.hooks.audit_sink.AuditSink.emit`.
        """
        self.calls.append(
            {
                "event": event,
                "correlation_id": correlation_id,
                "fields": dict(fields),
            }
        )


@pytest.fixture
def fresh_registry() -> Iterator[HookRegistry]:
    """Yield a brand-new :class:`HookRegistry` installed as the module
    singleton for the duration of the test.

    Captures the pre-test registry at fixture entry; restores it on
    teardown so the module-level singleton is bit-for-bit identical
    after the test (no leaked subscribers, no swapped gate). The gate
    is :func:`make_deny_all_gate` (a :class:`RealGate` over an
    empty-grants snapshot — every check denies) and the sink is the
    registry's own default :class:`StructlogAuditSink`.

    ``strict_declarations=False`` is set so the pre-#119 test bodies
    that register against ad-hoc hookpoint names without an explicit
    :meth:`HookRegistry.register_hookpoint` call continue to work.
    Production code (``alfred.memory.episodic`` et al) constructs the
    singleton with the default ``True``; tests that explicitly assert
    the strict contract use the :func:`strict_registry` fixture.
    """
    prior = get_registry()
    registry = HookRegistry(gate=make_default_test_gate(), strict_declarations=False)
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Like :func:`fresh_registry` but the gate accepts the ``system`` tier.

    Used by tests that legitimately register a system-tier subscriber
    (Task 7's @hook decorator tests, etc.). The default-deny on
    ``system`` is the production posture; this fixture is the explicit
    opt-in for tests that need to exercise the granted-system code
    path. Backed by :func:`make_allow_system_gate` — a :class:`RealGate`
    over a single wildcard ``system``-tier grant.

    ``strict_declarations=False`` — same rationale as
    :func:`fresh_registry`.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_default_test_gate(allow_system=True), strict_declarations=False
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def strict_registry() -> Iterator[HookRegistry]:
    """Yield a :class:`HookRegistry` with ``strict_declarations=True``
    — the production posture under #119.

    Tests in ``test_registration_enforcement.py`` use this to pin the
    strict-declaration contract (undeclared hookpoint refuses
    subscriber registration). The gate is :func:`make_allow_system_gate`
    so a test that exercises a system-tier subscriber on a declared
    hookpoint passes both gates.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_default_test_gate(allow_system=True),
        strict_declarations=True,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def spy_registry_allow_system(spy_sink: SpyAuditSink) -> Iterator[HookRegistry]:
    """Yield a :class:`HookRegistry` with a system-grant gate AND the
    shared :func:`spy_sink` injected as the audit sink.

    Tests that exercise the §6.5 refusal-authorization contract (Task 11)
    or the §6.7 reentry-bypass contract against system-tier subscribers
    (Task 12) need BOTH axes:

    * **System permitted at the gate** so a ``system``-tier subscriber
      can be registered without tripping the default-deny on the
      system tier. The gate comes from
      :func:`make_allow_system_gate`.
    * **Spy sink observable** so fault-path audit rows
      (:data:`HOOKS_REFUSAL`, :data:`HOOKS_UNAUTHORIZED_REFUSAL`,
      :data:`HOOKS_REENTRY_BYPASS`) land on the test recorder rather
      than the registry's default :class:`StructlogAuditSink`.

    Naming mirrors :func:`fresh_registry_allow_system` (tier axis first)
    then ``_with_spy``-style tail via the ``spy_`` prefix so a reader
    grepping ``spy_`` finds every spy-injected fixture in one shot. The
    sink is shared via the :func:`spy_sink` fixture so the test that
    requests both ``spy_registry_allow_system`` AND ``spy_sink`` sees
    the exact same recorder pytest hands to the registry constructor.

    Swap-and-restore the module singleton on teardown — same discipline
    as the other registry fixtures — so a test failing mid-run cannot
    leak the spy-injected registry into the next test.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_default_test_gate(allow_system=True),
        sink=spy_sink,
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def spy_sink() -> SpyAuditSink:
    """Return a fresh :class:`SpyAuditSink` per test.

    Tasks 9-12 inject this into a :class:`HookRegistry` constructor to
    assert the fault-path audit rows (one of the ``HOOKS_*`` event ids)
    fire exactly when the dispatcher decides to record one. The spy is
    a structural :class:`alfred.hooks.audit_sink.AuditSink` (the runtime
    Protocol's isinstance check passes).
    """
    return SpyAuditSink()
