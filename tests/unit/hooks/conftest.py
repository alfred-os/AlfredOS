"""Shared fixtures for ``tests/unit/hooks/`` — Slice-2.5 PR-A Task 6.

These fixtures are the test-side bookend of the :class:`HookRegistry`'s
gate-and-sink injection seams (spec §0 + the alfred-core-engineer-1
hardening). Every PR-A and PR-B test that exercises the registry consumes
one of them — never instantiating a registry by hand at test scope —
because the registry is the module-level singleton seam and per-test
isolation is enforced by :func:`alfred.hooks.registry.set_registry` /
:func:`get_registry` swap-and-restore, NOT by a fresh module import.

Three fixtures ship:

* :func:`fresh_registry` — the canonical default. Installs a brand-new
  :class:`HookRegistry` with a :class:`DevGate` (system tier denied) and
  the registry's own default :class:`StructlogAuditSink`. The pre-test
  registry is captured at fixture entry and restored on teardown so
  cross-test contamination via the module-level singleton is impossible.
* :func:`fresh_registry_allow_system` — same shape, but the gate accepts
  ``system``-tier requests. Used by tests that need to register a
  system-tier subscriber (Task 7's @hook decorator unit tests, Task 9's
  chain-deadline tests, Task 12's reentry-guard tests).
* :func:`spy_sink` — a structural :class:`AuditSink` test double that
  records every ``emit(event, correlation_id, fields)`` into a flat
  list. Tasks 9-12 inject this into a :class:`HookRegistry` to assert the
  fault-path audit rows (`hooks.refusal`, `hooks.chain_timeout`,
  `hooks.subscriber_error`, `hooks.unauthorized_refusal`,
  `hooks.reentry_bypass`) without depending on global structlog state.

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

from alfred.hooks.capability import DevGate
from alfred.hooks.registry import HookRegistry, get_registry, set_registry


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
    is a default :class:`DevGate` (``allow_system=False``); the sink is
    the registry's own default :class:`StructlogAuditSink`.
    """
    prior = get_registry()
    registry = HookRegistry(gate=DevGate())
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
    opt-in for tests that need to exercise the granted-system code path.
    """
    prior = get_registry()
    registry = HookRegistry(gate=DevGate(allow_system=True))
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
