"""``InboundDisposition`` — the injectable per-notification routing strategy.

Spec B G6-7-2 (#309). The single-reader pump in
:class:`alfred.plugins.comms_runner.CommsPluginRunner` fans every plugin -> host
notification into a *disposition*: a strategy object that routes ONE notification
and owns the never-raise (fire-and-forget) contract. Factoring it out behind a
Protocol lets the future gateway forward-runner (G6-7-3) inject a session-LESS
disposition that forwards inbound frames rather than dispatching them into a local
:class:`alfred.plugins.session.AlfredPluginSession`.

:class:`SessionDispatchDisposition` is the DEFAULT (daemon) disposition — the
verbatim routing the runner used to inline. The pump constructs one when no
disposition is injected, so the daemon's behaviour is byte-for-byte unchanged.

**Import-cycle rule (HARD):** this module MUST NOT import ``comms_runner``;
``comms_runner`` imports FROM here. Every shared symbol is imported from its
canonical home (the comms-MCP protocol/resolver/observer modules and the plugin
session), so the dependency edge stays one-directional.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog
from pydantic import ValidationError

from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)
from alfred.comms_mcp.adapter_credential_resolver import (
    AdapterCredentialAuditWriteError,
    AdapterCredentialError,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusAuditWriteError
from alfred.plugins.comms_stdio_transport import CommsProtocolError

if TYPE_CHECKING:
    from alfred.plugins.session import AlfredPluginSession

log = structlog.get_logger(__name__)

# Closed-vocab restart reason for a failed signed-audit write while recording a
# ``gateway.adapter.*`` status transition (SEC-1, Spec B G6-2b-2a / #288).
_STATUS_AUDIT_UNWRITABLE_RESTART_REASON: Final[str] = "status_audit_unwritable"

# Closed-vocab restart reason for a failed signed-audit write while recording a
# credential GRANT/refusal on the spawn-request path (ERR-G63-01, Spec B G6-3 / #288).
# A failed audit of "a real platform credential was released" is non-skippable.
_CREDENTIAL_AUDIT_UNWRITABLE_RESTART_REASON: Final[str] = "credential_audit_unwritable"


@runtime_checkable
class _CredentialResolverLike(Protocol):
    """Structural seam for the core-side credential resolver (Spec B G6-3 / #288).

    The concrete type is
    :class:`alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`;
    the disposition binds to this Protocol so it stays free of the comms-MCP resolver's
    construction deps. ``resolve`` raises ``AdapterCredentialError`` on a fail-closed
    refusal (which the disposition drops loud — NO grant sent).
    """

    async def resolve(self, request: SpawnRequest) -> object: ...


@runtime_checkable
class _SendNotification(Protocol):
    """The injected id-less notification writer the disposition sends grants through.

    Satisfied by :meth:`alfred.plugins.comms_runner.CommsPluginRunner.send_notification`
    — the disposition writes ``core.adapter.spawn_grant`` through it but does NOT own
    the transport, so the runner injects its bound method.
    """

    async def __call__(self, method: str, params: Mapping[str, object]) -> None: ...


@runtime_checkable
class _RequestRestart(Protocol):
    """The injected restart-request callable the disposition escalates through.

    Satisfied by :meth:`alfred.plugins.comms_runner.CommsPluginRunner._request_restart`
    — the disposition asks for a restart on a non-skippable failed-audit-write, but the
    runner owns the supervisor wiring, so it injects its bound method.
    """

    async def __call__(self, *, reason: str) -> None: ...


@runtime_checkable
class InboundDisposition(Protocol):
    """Strategy that routes ONE child notification — the pump's injectable seam.

    :meth:`dispatch` routes a single plugin -> host notification. It MUST NOT raise:
    the pump schedules it fire-and-forget via ``ensure_future`` whose done-callback
    never retrieves the result, so an escaping exception would reach no awaiter and
    merely leak a GC-time "Task exception was never retrieved" warning. Every terminal
    disposition (including the non-skippable failed-audit-write escalation) is therefore
    handled INSIDE ``dispatch`` rather than propagated.
    """

    async def dispatch(
        self, method: str, params: object, *, wire_seq: int | None = None
    ) -> None: ...


class SessionDispatchDisposition:
    """The DEFAULT (daemon) disposition: dispatch into a local plugin session.

    Owns the verbatim per-notification routing the runner used to inline in
    ``_route_notification`` + ``_route_spawn_request``: intercept the credential
    ``gateway.adapter.spawn_request`` round-trip (when a resolver is wired), else fan the
    notification into the session's validated dispatch arm. Every error arm is loud and
    NEVER re-raises (fire-and-forget — see :class:`InboundDisposition`).
    """

    def __init__(
        self,
        *,
        session: AlfredPluginSession,
        credential_resolver: _CredentialResolverLike | None,
        adapter_id: str,
        send_notification: _SendNotification,
        request_restart: _RequestRestart,
    ) -> None:
        self._session = session
        self._credential_resolver = credential_resolver
        self._adapter_id = adapter_id
        self._send_notification = send_notification
        self._request_restart = request_restart

    async def dispatch(self, method: str, params: object, *, wire_seq: int | None = None) -> None:
        """Fan one notification into the session; survive a single handler failure.

        The session's dispatch arm RE-RAISES a handler exception (err-007 — it has
        already emitted ``COMMS_HANDLER_FAILED`` + counted toward the breaker). The
        disposition catches it here and continues to the next frame, matching the
        session docstring's "the reader logs + continues" contract.

        This coroutine is ALWAYS run FIRE-AND-FORGET — the pump
        (``_spawn_notification_dispatch``) is its only production caller, scheduling it
        via ``ensure_future`` whose done-callback (the pump's ``_inflight`` ``discard``)
        never retrieves the result. So an exception that escaped here would NOT propagate
        anywhere a caller awaits — it would only surface as a GC-time "Task exception was
        never retrieved" warning. Every terminal disposition is therefore handled HERE:
        the method never raises, and the failed-audit-write escalation below is what
        makes that fault non-skippable (NOT a re-raise — there is no awaiter to catch
        one).

        ``wire_seq`` (Spec A G4b-2a-pre / ADR-0032) is THIS frame's out-of-band wire
        seq, threaded into the session's validated dispatch so it reaches
        ``model_validate`` bound to its own frame (F1); ``None`` for stdio.
        """
        params_mapping = params if isinstance(params, Mapping) else None
        # Spec B G6-3 (#288): intercept the credential request BEFORE the session
        # dispatch — a ``gateway.adapter.spawn_request`` is a request/response on the
        # leg the runner owns (the session has no send-back). Routed to the resolver +
        # the grant sent on this transport; never falls into the status-observer prefix
        # catch (which would refuse it as unknown_method). Only when a resolver is wired.
        if method == GATEWAY_ADAPTER_SPAWN_REQUEST and self._credential_resolver is not None:
            await self._route_spawn_request(params_mapping)
            return
        try:
            await self._session._on_post_handshake_method(method, params_mapping, wire_seq=wire_seq)
        except AdapterStatusAuditWriteError:
            # SEC-1 (Spec B G6-2b-2a / #288): a FAILED signed-audit write for a
            # ``gateway.adapter.*`` status transition is NOT an ordinary handler
            # fault — it is a non-skippable security event (CLAUDE.md hard rules
            # #5/#7). It MUST NOT fall into the blanket catch-and-continue below
            # (which would silently downgrade it to a structlog warning). The LOUD
            # escalation IS the teardown for a failed non-skippable audit write: a
            # ``log.error`` row + a restart request (the runner's quarantine/restart
            # path). We do NOT re-raise — this coroutine only ever runs
            # fire-and-forget (see the method docstring), so a re-raise would reach
            # no awaiter and merely leak an unretrieved-task-exception warning. The
            # escalation, not propagation, is what defeats the blanket catch-and-
            # continue.
            log.error(
                "comms.runner.status_audit_unwritable",
                adapter_id=self._adapter_id,
                notification_method=method,
            )
            try:
                await self._request_restart(reason=_STATUS_AUDIT_UNWRITABLE_RESTART_REASON)
            except Exception:
                # CR #297: the audit-write failure is ALREADY escalated loudly (the
                # log.error above). If the restart REQUEST itself raises, log it and
                # swallow — this coroutine runs fire-and-forget, so propagating would only
                # leak an unretrieved-task-exception warning (it reaches no awaiter), not
                # add any teardown. The loud security signal stands; we never go silent.
                log.error(
                    "comms.runner.status_audit_restart_request_failed",
                    adapter_id=self._adapter_id,
                    notification_method=method,
                )
        except Exception:
            # Catch-and-continue: the session already audited + counted this
            # failure. The reader must survive so a single bad handler does not
            # silence the whole adapter (err-007 invariant).
            log.warning(
                "comms.runner.handler_failed_continuing",
                adapter_id=self._adapter_id,
                notification_method=method,
            )

    async def _route_spawn_request(self, params: Mapping[str, object] | None) -> None:
        """Resolve a ``gateway.adapter.spawn_request`` + send back the grant (G6-3).

        The credential round-trip's core half. Validates the request frame, calls the
        resolver (the ONLY decryptor), and sends ``core.adapter.spawn_grant`` back on
        this transport (the runner owns the leg; the session does not). Runs
        fire-and-forget like every ``dispatch`` body, so it NEVER raises:

        * a malformed request -> loud drop, NO grant (the gateway's bounded await times
          out fail-closed);
        * a fail-closed ``AdapterCredentialError`` -> loud drop, NO grant (the resolver
          already audited the refusal);
        * a FAILED signed-audit write (``AdapterCredentialAuditWriteError``) ->
          ESCALATE loud (``log.error`` + a restart request), NEVER a silent swallow
          (ERR-G63-01 / hard rule #7) — the SAME SEC-1 arm the status path uses;
        * a send fault -> loud drop (the leg is gapped; the gateway re-requests).

        The grant frame carries the plaintext credential over the trusted leg only; the
        :class:`SpawnGrant` model is repr-safe, so the loud-drop logs never leak it.
        """
        assert self._credential_resolver is not None  # routed only when wired
        try:
            request = SpawnRequest.model_validate(params or {})
        except ValidationError:
            # No exc detail logged (it could echo the raw wire). Loud drop (hard rule #7).
            log.warning("comms.runner.spawn_request_malformed", adapter_id=self._adapter_id)
            return
        try:
            grant = await self._credential_resolver.resolve(request)
        except AdapterCredentialAuditWriteError:
            # ERR-G63-01 (#288): a FAILED signed-audit write while recording that a real
            # platform credential was RELEASED (or a refusal) is NOT an ordinary
            # fail-closed refusal — it is a non-skippable security event (CLAUDE.md hard
            # rules #5/#7). It MUST NOT be swallowed into the fire-and-forget dispatch
            # task as a GC-time "Task exception never retrieved" warning. The LOUD
            # escalation (a ``log.error`` row + a restart request) IS the teardown,
            # mirroring ``dispatch``'s status-observer SEC-1 arm. We do NOT
            # re-raise (this body runs fire-and-forget; a re-raise reaches no awaiter and
            # merely leaks an unretrieved-task-exception warning). The reason vocabulary
            # is closed; the credential is NEVER in the marker (cause is the bare backend
            # error) so nothing leaks. No grant is sent.
            log.error(
                "comms.runner.credential_audit_unwritable",
                adapter_id=self._adapter_id,
                request_id=request.request_id,
            )
            try:
                await self._request_restart(reason=_CREDENTIAL_AUDIT_UNWRITABLE_RESTART_REASON)
            except Exception:
                # The audit-write failure is ALREADY escalated loudly (the log.error
                # above). If the restart REQUEST itself raises, log + swallow — this body
                # runs fire-and-forget, so propagating only leaks an
                # unretrieved-task-exception warning (it reaches no awaiter). The loud
                # security signal stands; we never go silent.
                log.error(
                    "comms.runner.credential_audit_restart_request_failed",
                    adapter_id=self._adapter_id,
                    request_id=request.request_id,
                )
            return
        except AdapterCredentialError as exc:
            # The resolver already wrote the loud audited refusal; the runner just does
            # NOT send a grant (the gateway's bounded await fails closed). Log the
            # closed-vocab reason only — never the request/credential.
            log.warning(
                "comms.runner.spawn_request_refused",
                adapter_id=self._adapter_id,
                reason=exc.reason,
            )
            return
        if not isinstance(grant, SpawnGrant):  # pragma: no cover - resolver contract
            log.error("comms.runner.spawn_grant_type_invalid", adapter_id=self._adapter_id)
            return
        try:
            await self._send_notification(CORE_ADAPTER_SPAWN_GRANT, grant.model_dump())
        except (OSError, CommsProtocolError):
            # A send fault on a gapped leg: loud drop (the gateway re-requests on
            # reconnect). NEVER log the grant (repr-safe anyway) — only the routing id.
            # Narrowed to the known transport-fault family (broken pipe / reset are
            # ``OSError`` subclasses; a reframe-ceiling violation is ``CommsProtocolError``)
            # so a future logic bug is NOT absorbed as a benign send-drop (hard rule #7).
            log.warning(
                "comms.runner.spawn_grant_send_failed",
                adapter_id=self._adapter_id,
                request_id=request.request_id,
            )


__all__ = [
    "InboundDisposition",
    "SessionDispatchDisposition",
]
