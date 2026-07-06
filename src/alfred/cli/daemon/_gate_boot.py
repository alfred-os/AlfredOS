"""Daemon boot capability-gate wiring (#256 PR-2).

Extracted from ``_commands.py``: the seed-then-load boot gate
(:func:`build_boot_real_gate_for_daemon`, ADR-0026), the Postgres-connectivity
handshake for probe (c) (:class:`_BootHandshake` / :func:`build_boot_handshake`),
the fail-closed first-party grant assertion (:func:`_first_party_grant_live`,
ADR-0026), the boot :class:`HookRegistry` install
(:func:`_install_quarantine_boot_registry`), and the Supervisor-facing sync
backing-store gate wrapper (:class:`_SupervisorBootGate` over the typed
:class:`_BackingStoreAvailabilityGate` contract — no ``getattr`` fail-open).

Independent of both ``_boot_audit`` and ``_comms_boot``: ``_start_async`` (in
``_commands``) drives these via the re-imported names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.security.capability_gate._gate import RealGate


class _BackingStoreAvailabilityGate(Protocol):
    """The PUBLIC contract the supervisor boot gate depends on.

    arch-222-1 / err-001 / core-eng-pr222-1: the boot gate consumes
    :meth:`RealGate.is_backing_store_available` through this Protocol rather
    than reaching into the private ``_fail_closed`` attribute. A ``getattr``
    default would fail-OPEN (report "available") if the attribute were ever
    renamed; depending on a typed contract makes the bridge survive a
    refactor and keeps the fail-closed direction safe.
    """

    def is_backing_store_available(self) -> bool: ...


class _SupervisorBootGate:
    """Gate adapter the Supervisor consumes.

    Wraps a :class:`RealGate` (for the hot-path ``check*`` calls the plugin
    lifecycle will make) and re-exports the SYNC
    ``is_backing_store_available()`` the supervisor's
    ``CapabilityGateMonitor`` heartbeat polls. The wrapped gate's PUBLIC
    :meth:`is_backing_store_available` is the source of truth — it returns
    ``not _fail_closed`` (driven by RealGate's own heartbeat), so the
    monitor's transition logic stays correct. We delegate to that public
    method (no ``getattr`` default, no private reach) so a missing method is
    a loud ``AttributeError`` at construction-adjacent call time rather than
    a silent fail-OPEN.
    """

    def __init__(self, gate: _BackingStoreAvailabilityGate) -> None:
        self._gate = gate

    def is_backing_store_available(self) -> bool:
        return self._gate.is_backing_store_available()


class _BootHandshake:
    """Async Postgres-connectivity handshake the capability-gate probe uses.

    core-eng-002: this is where Postgres reachability is checked (probe c),
    via a real ``SELECT 1`` over the boot session scope. Distinct from the
    snapshot-ref probe (b), which is file-only.
    """

    def __init__(
        self,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def is_backing_store_available(self) -> bool:
        from alfred.memory.db import healthcheck

        await healthcheck(self._session_scope)
        return True


async def build_boot_real_gate_for_daemon(
    settings: Settings,
) -> RealGate:  # pragma: no cover - real-infra glue; unit tests monkeypatch
    """Construct the RAW seeded :class:`RealGate` (ADR-0026 seed-then-load).

    Builds the Postgres backend, then delegates to
    :func:`alfred.bootstrap.gate_factory.build_boot_real_gate` which seeds
    the first-party system grants BEFORE loading the in-memory policy. The
    gate is returned RAW (not wrapped in :class:`_SupervisorBootGate`) so
    :func:`_start_async` can (a) install it into the boot
    :class:`HookRegistry` and (b) run the post-install grant assertion
    against ``check`` before wrapping it for the Supervisor.

    ``start_heartbeat=True`` is load-bearing for runtime-outage detection:
    the supervisor's :class:`CapabilityGateMonitor` polls the wrapped
    gate's ``is_backing_store_available``, which reads the RealGate
    ``_fail_closed`` flag driven ONLY by the heartbeat loop. With the
    heartbeat OFF, a RUNTIME Postgres outage after boot would go
    undetected and the gate would never fail-closed. The boot-time
    liveness check is the separate async ``SELECT 1`` handshake (probe c);
    the heartbeat is the post-boot continuous check.

    ADR-0027: ``extra_grants`` carries the config-sourced comms-adapter
    plugin-LOAD grants derived from ``settings.comms_enabled_adapters`` by
    the pure :func:`comms_adapter_load_grants` builder (unit-covered in
    isolation). Empty for a default-empty config, so the boot seed is then
    EXACTLY :data:`FIRST_PARTY_SYSTEM_GRANTS`. A broken / ``system``-tier
    manifest for an enabled adapter raises out of the builder here
    (:class:`alfred.plugins.errors.ManifestError`) — as does an unreadable
    manifest file (:class:`OSError`) — fail-closed, rather than seeding
    nothing. The ``except (SQLAlchemyError, HookError, ManifestError, OSError)``
    / grant-assertion arms in :func:`_start_async` surface it as an audited
    ``boot_infra_install_failed`` refusal (exit 2 + a ``daemon.boot.failed``
    row), never a raw traceback.
    """
    from alfred.bootstrap.gate_factory import build_boot_real_gate
    from alfred.security.capability_gate._comms_adapter_grants import (
        comms_adapter_load_grants,
    )
    from alfred.security.capability_gate.backend import PostgresBackend

    backend = PostgresBackend(dsn=settings.database_url.unicode_string())

    async def _noop_audit_sink(**_kw: object) -> None:
        return None

    return await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink,
        start_heartbeat=True,
        extra_grants=comms_adapter_load_grants(settings),
    )


def _first_party_grant_live(gate: CapabilityGate) -> bool:
    """Return ``True`` iff every first-party system grant is live on ``gate``.

    ADR-0026: drives the assertion off the SAME
    :data:`FIRST_PARTY_SYSTEM_GRANTS` constant the seed uses, so the seed
    and the liveness check can never drift. A ``False`` means the
    seed-then-load did not project a grant into the in-memory policy — a
    structurally-broken trust boundary (e.g. the
    :class:`QuarantinedExtractor` could not register its DLP scan, or a
    real turn's tool dispatch would fail loud at the T3 content-clearance
    boundary).

    #339 PR3: :class:`GrantRow` carries TWO ORTHOGONAL axes (spec §4.3) —
    ``subscriber_tier`` (capability) and ``content_tier`` (trust). Each is
    verified on its OWN axis, matching how the production call sites gate:
    a ``content_tier is None`` row is a subscriber-tier-only grant (e.g. the
    DLP subscriber, ``tool.dispatch``) verified via :meth:`RealGate.check`;
    a row carrying a ``content_tier`` (e.g. ``quarantine.dereference``,
    ``t3.downgrade_to_orchestrator``) is verified via
    :meth:`RealGate.check_content_clearance`, which matches on
    ``content_tier`` and ignores ``subscriber_tier`` entirely. Checking a
    content-tier grant with :meth:`check` instead would silently pass
    (``check`` ignores ``content_tier``) without proving the content-tier
    boundary is actually clear — this branch is what makes the assertion
    faithful to what the runtime dispatch/quarantine call sites query.
    """
    from alfred.security.capability_gate._bootstrap_grants import (
        FIRST_PARTY_SYSTEM_GRANTS,
    )

    # Fail closed on an empty grant set: ``all(())`` is vacuously True, which
    # would let the boot assertion pass with NOTHING asserted. A trust boundary
    # with no first-party grant to verify is itself broken — refuse.
    if not FIRST_PARTY_SYSTEM_GRANTS:
        return False
    return all(
        (
            gate.check_content_clearance(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                content_tier=grant.content_tier,
            )
            if grant.content_tier is not None
            else gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
        )
        for grant in FIRST_PARTY_SYSTEM_GRANTS
    )


def _install_quarantine_boot_registry(gate: CapabilityGate, *, audit: AuditWriter) -> None:
    """Install the boot :class:`HookRegistry` over ``gate`` + the durable sink.

    The registry sink is the boot :class:`AuditWriter` wrapped in
    :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink` so a
    DLP-subscriber-deny refusal row is DURABLE (CLAUDE.md hard rule #7),
    NOT the gate's no-op sink. ``gate`` is the RAW :class:`RealGate` whose
    ``check`` consults the grant policy — passing the
    :class:`_SupervisorBootGate` wrapper (no ``check``) would be a
    fail-open smell the typed signature rejects.
    """
    from alfred.hooks.boot import install_boot_hook_registry
    from alfred.memory.hooks_audit_sink import EpisodicAuditSink

    install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))


def build_boot_handshake(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> _BootHandshake:
    """Build the async Postgres-connectivity handshake for probe (c)."""
    return _BootHandshake(session_scope)
