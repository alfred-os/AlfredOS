"""Bootstrap factory for capability-gate selection.

Spec §8.4: :class:`alfred.security.capability_gate._gate.RealGate` is the
production default; :class:`alfred.hooks.capability.DevGate` is the
development default. This module is the SINGLE allowed reader of
``ALFRED_ENV`` for the purpose of gate selection — sec-007 forbids the
read inside the gate logic itself, where an env-at-import-time read
would make construction depend on global state rather than injected
configuration.

The ``os.environ`` read in :func:`is_production` is the sec-007
exception. The capability-gate modules (``hooks/capability.py``,
``security/capability_gate/{policy,_gate,backend,proposals}.py``) MUST
NOT contain the literal string ``"ALFRED_ENV"`` — that invariant is
enforced by ``tests/unit/security/test_default_strict_declarations_invariant.py``
(behavioural) and ``tests/unit/security/test_capability_gate_ast_no_os_import.py``
(broader ``import os`` guard for the same modules).

Why three callables rather than one ``build_gate()`` factory:

* :func:`build_dev_gate` and :func:`build_real_gate` differ in their
  dependency set (DevGate is zero-dep; RealGate needs a
  :class:`StorageBackend` and an :class:`AuditWriter`). Pushing the env
  read down into a single ``build_gate()`` would either pull both
  dependency trees into bootstrap or hide the conditional from the
  call site.
* The call site (the supervisor bootstrap, PR-S3-3b) consults
  :func:`is_production` to decide which dependency tree to construct,
  then calls the matching builder explicitly. That keeps the
  dependency-construction sequencing visible at the call site.

This file deliberately does not import :class:`RealGate` at module
top-level — the import would pull SQLAlchemy + asyncpg into every
process that constructs a :class:`DevGate`. The lazy import inside
:func:`build_real_gate` keeps DevGate-only paths free of the heavy
dependency tree.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from alfred.hooks.capability import DevGate

if TYPE_CHECKING:
    from alfred.security.capability_gate._gate import RealGate
    from alfred.security.capability_gate.backend import StorageBackend


# Module-level constant for the env key name. Centralising the literal
# keeps the env-key vocabulary searchable (one ``grep`` site, not five).
# The name is deliberately bound at import time — runtime mutation
# would not change the bootstrap decision, which is a one-shot read at
# process start.
_ENV_KEY: str = "ALFRED_ENV"
_DEVELOPMENT: str = "development"


def is_production() -> bool:
    """Return :data:`True` when ``ALFRED_ENV`` is anything but ``"development"``.

    Spec §8.4: RealGate is the production default. An unset env var,
    an empty string, or the explicit ``"development"`` sentinel all map
    to development; everything else (``"production"``, ``"staging"``,
    a typo'd label like ``"prdouction"``) maps to production so the
    safer gate wins on operator error.

    This is the SINGLE sanctioned ``os.environ`` read for gate
    selection in the entire ``src/alfred/`` tree. Adding another would
    break the sec-007 invariant pinned by
    ``test_default_strict_declarations_invariant.py``.
    """
    value = os.environ.get(_ENV_KEY, _DEVELOPMENT)
    return value != _DEVELOPMENT


def build_dev_gate() -> DevGate:
    """Construct the development-default :class:`DevGate`.

    Spec §8.4: DevGate's :meth:`check_plugin_load` and
    :meth:`check_content_clearance` are fail-open stubs through
    Slice 3 (flag-day removal in PR-S3-7). The bootstrap default is
    ``allow_system=False`` — the safer posture. A developer who needs
    system-tier access in a one-off script can construct
    ``DevGate(allow_system=True)`` directly; the bootstrap factory
    does not surface the flag because the production-equivalent path
    (RealGate consulting a grant table) has no analogue.
    """
    return DevGate()


async def build_real_gate(
    *,
    backend: StorageBackend,
    audit_sink: object,
    start_heartbeat: bool = True,
) -> RealGate:
    """Construct the production-default :class:`RealGate`.

    Args:
        backend: A :class:`StorageBackend` implementation. Production
            wiring passes :class:`PostgresBackend`; tests inject a
            double matching the same Protocol.
        audit_sink: An object whose :meth:`append_schema` matches the
            structural Protocol :class:`RealGate` checks against. The
            production sink is :class:`alfred.audit.log.AuditWriter`.
            Required per err-003: a fail-closed state transition with
            no audit row is a silent security-state transition, which
            CLAUDE.md hard rule #7 forbids.
        start_heartbeat: ``True`` in production (the supervisor calls
            :meth:`RealGate.stop_heartbeat` at graceful shutdown);
            ``False`` in unit tests where the background task would
            race the runner.

    The :class:`RealGate` import is lazy so DevGate-only callers do
    not pay the SQLAlchemy + asyncpg import cost. The factory is
    ``async`` because :meth:`RealGate.create` runs the initial
    Postgres grant load before returning a ready instance.
    """
    from alfred.security.capability_gate._gate import RealGate

    return await RealGate.create(
        backend=backend,
        audit_sink=audit_sink,  # type: ignore[arg-type]
        start_heartbeat=start_heartbeat,
    )
