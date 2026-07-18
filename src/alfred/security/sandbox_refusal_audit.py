"""Persist launcher sandbox-refusal rows + dispatch the fail-closed hookpoint (#433).

The reusable half of the launcher->core audit path (ADR-0051). Given validated
:class:`alfred.audit.launcher_refusal.SandboxRefusalRow` values, writes each as a
``supervisor.plugin.sandbox_refused`` audit row (symmetric ``SANDBOX_REFUSED_FIELDS``
key-set) and dispatches the registered ``fail_closed`` T0 hookpoint, mirroring
``cli/daemon/_boot_audit.py:_invoke_boot_failed``.

``alfred.hooks`` is imported lazily (function-local), mirroring ``_boot_audit.py``
and respecting the known ``hooks -> security.tiers`` back-import.

The quarantine-child spawn is the first adopter. As of the #443 PR2 two-frame
boot handshake, dispatch now happens AT BOOT, inside the spawn handshake
(``_await_boot_handshake``, read from inside ``spawn_quarantine_child_io``) —
strictly before ``Supervisor`` is constructed. That is safe only because PR1
(``alfred.supervisor.hookpoints.declare_hookpoints``) made the supervisor's
hookpoints boot-declarable, registered at the ``hooks/boot.py`` seam ahead of
the spawn; see ADR-0051's "Amendment (#443 PR2 — boot-time handshake)" section
for the full history (this docstring previously asserted the dispatch happened
post-``Supervisor``, which PR2 inverted). The three other producers do NOT
simply adopt this auditor: the comms-adapter (#440) and gateway-adapter (#441)
PIPE their child's stderr but never READ it today (verified —
``comms_stdio_transport.py:173`` / ``adapter_child_factory.py:497``), so they
must first BUILD an stderr drain before this auditor has any bytes to persist;
and the foreground-TUI producer
(``cli/_launcher_spawn.spawn_plugin_via_launcher``, #442) has ZERO production
call sites (``alfred chat`` dials the gateway socket, Spec A G5), so #442 is a
rescope-to-delete the dead seam, not an adoption. See ADR-0051's §8.2 amendment
for the verified stderr-draining picture. ``record`` raising is the caller's
contract to handle (the quarantine drain guards it so it never masks the
refusal).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Protocol

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS

if TYPE_CHECKING:
    from alfred.audit.launcher_refusal import SandboxRefusalRow
    from alfred.audit.log import AuditWriter


class SandboxRefusalRecorder(Protocol):
    """Narrow seam a launcher-spawn site calls to persist its refusals."""

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        """Persist the host-authored ``provider_key_delivery_failed`` row (#444)."""
        ...


_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"


class SandboxRefusalAuditor:
    """Writes ``sandbox_refused`` rows + dispatches the fail-closed hookpoint."""

    def __init__(self, *, audit_writer: AuditWriter, host_os: str, environment: str) -> None:
        self._audit = audit_writer
        self._host_os = host_os
        self._environment = environment

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        """Persist the reserved ``provider_key_delivery_failed`` row (#444).

        HOST-authored, not launcher-parsed: the parent's own ``os.writev`` over fd 3
        failed while the child was still up (partial write / EAGAIN), so there is no
        launcher stderr to parse. Every field is a trusted host constant (no T3), and
        the write reuses ``record`` for the durable ``append_schema`` + the T0
        ``fail_closed`` hookpoint dispatch (declared at ``hooks/boot.py`` ahead of the
        spawn — ADR-0051's #443 PR2 amendment).
        """
        from alfred.audit.launcher_refusal import SandboxRefusalRow

        # ``reason`` is the reserved constant ``ProviderKeyDeliveryError`` raises with
        # (``fd3_key_delivery.py``) — hard-coded here (not read from the exception) so a
        # caller cannot inject a reason outside ``SANDBOX_REFUSED_REASONS``. Keep the two
        # bound: if the exception's default reason ever changes, change this literal too.
        row = SandboxRefusalRow(
            plugin_id=plugin_id,
            policy_ref="",
            host_os=self._host_os,
            reason="provider_key_delivery_failed",
            environment=self._environment,
        )
        await self.record((row,))

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        from alfred.hooks import SYSTEM_ONLY_TIERS
        from alfred.hooks.context import HookContext
        from alfred.hooks.invoke import invoke

        for row in rows:
            correlation_id = str(uuid.uuid4())
            await self._audit.append_schema(
                fields=SANDBOX_REFUSED_FIELDS,
                schema_name="SANDBOX_REFUSED_FIELDS",
                event=_REFUSED_EVENT,
                actor_user_id=None,
                actor_persona="supervisor",
                subject=row.as_subject(),
                trust_tier_of_trigger="T0",
                result="refused",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=correlation_id,
            )
            ctx: HookContext[dict[str, object]] = HookContext(
                action_id=_REFUSED_EVENT,
                hookpoint=_REFUSED_EVENT,
                input={"reason": row.reason, "correlation_id": correlation_id},
                correlation_id=correlation_id,
                kind="post",
            )
            await invoke(
                _REFUSED_EVENT,
                ctx,
                kind="post",
                subscribable_tiers=SYSTEM_ONLY_TIERS,
                fail_closed=True,
            )


__all__ = ["SandboxRefusalAuditor", "SandboxRefusalRecorder"]
