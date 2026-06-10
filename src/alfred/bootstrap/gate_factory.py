"""Bootstrap factory for capability-gate selection.

Spec §8.4: :class:`alfred.security.capability_gate._gate.RealGate` is
the production gate. PR-S3-7 (spec §15.1 flag-day) removed the dev-time
:class:`DevGate` from ``src/`` entirely; this factory now constructs a
:class:`RealGate` in BOTH the development and production branches —
the development branch wires it with no grants (so every check denies
fail-closed) and skips the heartbeat, the production branch wires the
full Postgres-backed grant table with the heartbeat running.

The :func:`is_production` env read is the SINGLE allowed reader of
``ALFRED_ENV`` for the purpose of gate selection — sec-007 forbids the
read inside the gate logic itself, where an env-at-import-time read
would make construction depend on global state rather than injected
configuration.

The capability-gate modules (``hooks/capability.py``,
``security/capability_gate/{policy,_gate,backend,proposals}.py``) MUST
NOT contain the literal string ``"ALFRED_ENV"`` — that invariant is
enforced by ``tests/unit/security/test_default_strict_declarations_invariant.py``
(behavioural) and ``tests/unit/security/test_capability_gate_ast_no_os_import.py``
(broader ``import os`` guard for the same modules).

Why two callables rather than one ``build_gate()`` factory:

* :func:`build_dev_gate` and :func:`build_real_gate` differ in their
  dependency set. ``build_dev_gate`` constructs a no-grant
  :class:`RealGate` over an in-memory stub backend; ``build_real_gate``
  needs a real :class:`StorageBackend` and an :class:`AuditWriter`.
  Pushing the env read down into a single ``build_gate()`` would
  either pull both dependency trees into every bootstrap path or hide
  the conditional from the call site.
* The call site (the supervisor bootstrap, PR-S3-3b) consults
  :func:`is_production` to decide which dependency tree to construct,
  then calls the matching builder explicitly. That keeps the
  dependency-construction sequencing visible at the call site.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import structlog

from alfred.i18n import t
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow

_log = structlog.get_logger(__name__)

if TYPE_CHECKING:
    from alfred.security.capability_gate._audit_protocols import _AuditSink
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
    an empty string (including whitespace-only), or the explicit
    ``"development"`` sentinel all map to development; everything else
    (``"production"``, ``"staging"``, a typo'd label like
    ``"prdouction"``) maps to production so the safer gate wins on
    operator error.

    Empty-string handling: ``os.environ.get(_ENV_KEY, _DEVELOPMENT)``
    only returns the default when the key is absent; a present-but-empty
    ``ALFRED_ENV=""`` (a common misconfiguration in shell-export chains
    where a variable is exported with no value) used to fall through to
    production. The ``.strip()`` + closed-domain check below treats
    empty / whitespace as missing — same as the documented contract.

    This is the SINGLE sanctioned ``os.environ`` read for gate
    selection in the entire ``src/alfred/`` tree. Adding another would
    break the sec-007 invariant pinned by
    ``test_default_strict_declarations_invariant.py``.
    """
    value = os.environ.get(_ENV_KEY, "").strip()
    return value not in {"", _DEVELOPMENT}


def _make_in_memory_backend(grants: Iterable[GrantRow] = ()) -> StorageBackend:
    """Return a :class:`StorageBackend`-shaped stub with no Postgres I/O.

    PR-S3-7 (spec §15.1): with :class:`DevGate` removed, the development
    bootstrap path constructs a :class:`RealGate` over an in-memory
    backend stub instead of touching Postgres. The stub satisfies the
    structural :class:`StorageBackend` Protocol without any database
    connection so ``alfred chat`` / ``alfred status`` in a development
    environment doesn't depend on a running database.

    Return type is the :class:`StorageBackend` Protocol, not :class:`Any`:
    the Protocol is ``@runtime_checkable`` and the caller
    (:func:`build_dev_gate`) feeds the result to
    :class:`RealGate.__init__`'s ``backend: StorageBackend`` parameter
    so the structural type hint is the load-bearing contract. A future
    addition to the Protocol surfaces here as a mypy failure rather
    than a silent runtime :class:`AttributeError`.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset(grants))
    backend.get_sync_hash = AsyncMock(return_value=None)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    backend.seed_first_party_grants = AsyncMock(return_value=None)
    backend.reconcile_comms_adapter_grants = AsyncMock(return_value=None)
    return backend


def _make_no_op_audit_sink() -> _AuditSink:
    """Return an audit-sink stub for the development gate.

    err-003: :class:`RealGate` requires an audit sink so fail-closed
    state transitions cannot land silently. The development bootstrap
    doesn't have a real :class:`AuditWriter` wired (no Postgres
    backend), so a stub satisfies the constructor contract — and the
    no-grant policy means the gate denies every check on the hot path
    without ever transitioning to fail-closed (no heartbeat) so the
    sink is never called in practice.

    Return type is the :class:`_AuditSink` Protocol (shared with
    :mod:`alfred.security.capability_gate.proposals` per
    :mod:`alfred.security.capability_gate._audit_protocols`) so the
    caller's :class:`RealGate.__init__` ``audit_sink: _AuditSink``
    parameter binds against a structural Protocol rather than an
    untyped :class:`Any`. A future addition to the Protocol surfaces
    here as a mypy failure rather than a silent runtime
    :class:`AttributeError`.
    """
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def build_dev_gate() -> RealGate:
    """Construct the development-default gate — a fail-closed :class:`RealGate`.

    Spec §15.1 (flag-day): :class:`DevGate` was removed from ``src/``
    in PR-S3-7. The development bootstrap now constructs a
    :class:`RealGate` with an empty grant snapshot and an in-memory
    backend stub (no Postgres). Every :meth:`RealGate.check` call
    denies fail-closed — the only safe default when no operator-grant
    table is wired. Developers who need granted-system semantics for
    local iteration should construct the gate via the test helpers in
    :mod:`tests.helpers.gates` or stand up a real Postgres + seeded
    grants table.

    The heartbeat is NOT started: with the stub backend's ping always
    succeeding, the heartbeat would loop forever doing nothing, and a
    development supervisor that never calls
    :meth:`RealGate.stop_heartbeat` would leak the task at shutdown.

    DEVEX-004: emits an INFO-level structlog event so the operator's
    log stream visibly carries which gate is wired at bootstrap. The
    development gate denies every check by default — operators should
    never see this in production. The event name is closed-vocabulary
    so log filters can alert on it directly.
    """
    raw_env = os.environ.get(_ENV_KEY, "").strip()
    # Translators: load-bearing security vocabulary. "Fail-closed" means
    # every capability check DENIES until an operator-issued grant lands;
    # do NOT swap it for "fail-open" (the inverted semantics shipped in
    # the pre-flag-day DevGate). The string surfaces on operator
    # dashboards as the warning field on the bootstrap.gate_selected
    # structlog event; the word "production" must remain so the
    # invariant test in
    # tests/unit/security/test_default_strict_declarations_invariant.py
    # (which asserts ``"production" in entry["warning"].lower()``)
    # continues to hold across localisations.
    _log.info(
        "bootstrap.gate_selected",
        gate="DevelopmentRealGate",
        alfred_env=raw_env or "(unset)",
        warning=t("bootstrap.gate_selected.dev_default"),
    )
    return RealGate(
        policy=GatePolicy(grants=frozenset()),
        backend=_make_in_memory_backend(),
        audit_sink=_make_no_op_audit_sink(),
    )


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

    PR-S3-7 (spec §15.1) folded the development branch onto the same
    :class:`RealGate` type (with a stub backend and no heartbeat) so
    the import graph is symmetric — :class:`RealGate` is imported at
    module top-level rather than lazily inside this function, since
    both :func:`build_dev_gate` and :func:`build_real_gate` need it.
    The factory is ``async`` because :meth:`RealGate.create` runs the
    initial Postgres grant load before returning a ready instance.
    """
    # DEVEX-004: emit the bootstrap-time gate-selected event before the
    # await so the log line ALWAYS lands even if RealGate.create fails
    # (the failure shape is useful operator forensics with this context).
    # The raw_env value lets an operator who typo'd "prdouction" see
    # the exact string the bootstrap read.
    raw_env = os.environ.get(_ENV_KEY, "").strip()
    _log.info(
        "bootstrap.gate_selected",
        gate="RealGate",
        alfred_env=raw_env or "(unset)",
    )
    return await RealGate.create(
        backend=backend,
        audit_sink=audit_sink,  # type: ignore[arg-type]
        start_heartbeat=start_heartbeat,
    )


async def build_boot_real_gate(
    *,
    backend: StorageBackend,
    audit_sink: object,
    start_heartbeat: bool = True,
    extra_grants: Iterable[GrantRow] = (),
) -> RealGate:
    """Construct a production :class:`RealGate` with first-party grants seeded.

    ADR-0026 seed-then-load ordering, encapsulated in ONE place:

    1. ``await backend.seed_first_party_grants((*FIRST_PARTY_SYSTEM_GRANTS,
       *extra_grants))`` lands AlfredOS's own defences (the system-tier
       ``security.quarantined.extract`` DLP subscriber) PLUS any
       config-sourced ``extra_grants`` into ``plugin_grants`` as
       ``approved`` rows, in ONE transaction. Additive only — the seed
       never runs the revoke-diff, so an operator grant is never removed.
    2. :meth:`RealGate.create` then reads the grant snapshot via
       ``load_grants``, so the in-memory policy already contains the
       first-party grants the moment the gate is returned.

    ``extra_grants`` (ADR-0027) carries the config-sourced
    comms-adapter plugin-LOAD grants the daemon derives from
    ``Settings.comms_enabled_adapters`` (see
    :func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`).
    It defaults to ``()`` so every non-daemon caller (and a default-empty
    daemon boot) seeds EXACTLY the static :data:`FIRST_PARTY_SYSTEM_GRANTS`,
    byte-for-byte unchanged. The static seed is unchanged; the extra grants
    are purely additive.

    This ordering is load-bearing: the daemon constructs a
    :class:`alfred.security.quarantine.QuarantinedExtractor` immediately
    after this gate, and that constructor's DLP-subscriber registration
    is denied by the gate unless the seeded grant is already in the
    loaded policy. Doing the seed AFTER ``create`` would load an empty
    policy and deny the extractor (the silent half-wired-extractor shape
    CLAUDE.md hard rule #7 forbids).

    This is NOT a fail-open: the gate still denies every registration not
    covered by an ``approved`` grant. The ONLY newly-authorised
    registration is the seeded first-party DLP subscriber — the gate is
    NOT special-cased to "trust first-party by module name".

    A :class:`sqlalchemy.exc.SQLAlchemyError` from the seed propagates
    (Postgres-down / write failure) so a failed seed refuses boot rather
    than constructing a gate over an unseeded policy.

    Args:
        backend: A :class:`StorageBackend` implementation (production:
            :class:`alfred.security.capability_gate.backend.PostgresBackend`).
        audit_sink: The fail-closed-transition audit sink RealGate
            requires (err-003).
        start_heartbeat: ``True`` in production so the supervisor's
            monitor observes a later Postgres outage; ``False`` in unit
            tests where the background task would race the runner.
        extra_grants: Config-sourced grants to seed ALONGSIDE the static
            first-party constant (ADR-0027 comms-adapter load grants).
            Defaults to ``()`` — the static seed is then byte-for-byte
            unchanged.

    Returns:
        A ready :class:`RealGate` whose policy includes
        :data:`FIRST_PARTY_SYSTEM_GRANTS` (and any ``extra_grants``).
        Returned RAW (not wrapped in the supervisor boot-gate adapter) so
        the caller can run the post-install grant assertion against
        ``check`` and install it into the boot
        :class:`alfred.hooks.registry.HookRegistry`.
    """
    from alfred.security.capability_gate._bootstrap_grants import (
        FIRST_PARTY_SYSTEM_GRANTS,
    )

    await backend.seed_first_party_grants((*FIRST_PARTY_SYSTEM_GRANTS, *extra_grants))
    # FIX 2 (PR-S4-11b review): the static seed above is ADDITIVE-only, which is
    # correct for the never-removed :data:`FIRST_PARTY_SYSTEM_GRANTS` but leaves
    # a STALE comms-adapter load grant in Postgres when an operator REMOVES an
    # adapter (the comms-adapter grants are DYNAMIC, driven by
    # ``comms_enabled_adapters``). Reconcile them so the
    # ``bootstrap:first-party-comms-adapter`` rows in Postgres EXACTLY mirror the
    # current config: the scoped revoke-diff drops any sentinel-branch row not in
    # ``extra_grants`` and (idempotently) re-upserts the desired set, in one
    # transaction. The revoke WHERE is pinned to the comms-adapter sentinel, so it
    # never touches the DLP system grant or an operator grant. Runs BEFORE
    # ``RealGate.create`` so the in-memory policy load reflects the reconciled
    # state.
    await backend.reconcile_comms_adapter_grants(extra_grants)
    return await RealGate.create(
        backend=backend,
        audit_sink=audit_sink,  # type: ignore[arg-type]
        start_heartbeat=start_heartbeat,
    )
