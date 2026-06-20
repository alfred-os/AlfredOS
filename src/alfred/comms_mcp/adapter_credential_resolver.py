"""``CoreAdapterCredentialResolver`` — the ONLY platform-credential decryptor (G6-3).

Core-side half of the heaviest trust boundary in Spec B (#288). The gateway sends a
:class:`alfred.comms_mcp.adapter_credential_protocol.SpawnRequest` over the trusted
ADR-0031 leg; this resolver maps ``adapter_id -> secret_id`` via a CLOSED allowlist,
reads the platform credential from the secret broker, and returns a
:class:`SpawnGrant`. It is wired into the daemon's comms boot graph (parallels
``adapter_status_observer.py``, built in ``_build_comms_boot_graph``) and is the
boot graph's single decryptor — the gateway holds no vault key.

**Confused-deputy defence (L4 / adversarial a).** :data:`_ADAPTER_SECRET_ALLOWLIST`
is a closed map. An ``adapter_id`` with no entry is a typed refusal — the resolver
NEVER calls ``broker.get(adapter_id)`` with an attacker-influenced name.

**Epoch-bound + dedup (H3 / H4).** The canonical dedup/replay key is
``(adapter_id, host_restart_seq, epoch)``. The per-core-boot ``epoch`` is
load-bearing: ``host_restart_seq`` resets on a gateway restart, so the pair alone is
replayable across a gateway bounce. A true replay (all three match) returns the SAME
credential with ``broker.get`` called EXACTLY ONCE (no decrypt-storm/oracle) and is
audited ``duplicate=true``; it is flagged, never suppressed (hard rule #7).

**Fail-closed + structurally un-loggable error (S-C3 / C3).** Unknown adapter /
missing secret / (future) wrong-epoch is a loud, audited :class:`AdapterCredentialError`
built from ``adapter_id`` + a closed-vocab reason ONLY — never ``from`` a
``ValidationError`` carrying raw input, never with the credential or the frame in
``args``. No audit row carries the credential (the field is structurally absent from
:data:`alfred.audit.audit_row_schemas.CORE_ADAPTER_SPAWN_GRANT_FIELDS`).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, NoReturn, Protocol

import structlog

from alfred.audit.audit_row_schemas import CORE_ADAPTER_SPAWN_GRANT_FIELDS
from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    SpawnGrant,
    SpawnRequest,
)
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security.secrets import UnknownSecretError

log = structlog.get_logger(__name__)

# The CLOSED adapter -> secret-id allowlist (L4 confused-deputy defence). Only the
# adapters that actually carry a platform credential appear here; an unknown id (or a
# credential-less adapter like ``tui``) is a typed refusal, never a broker passthrough.
_ADAPTER_SECRET_ALLOWLIST: Final[dict[str, str]] = {
    "discord": "discord_bot_token",
}

# Core-owned control metadata (NOT a T3 message body) audits at T0 — the SAME tier
# the gateway.adapter.* status rows and the daemon.lifecycle.* rows use.
_CREDENTIAL_TRUST_TIER: Final[str] = "T0"

# Closed-vocabulary refusal reasons (mirrors quarantine_child_io's reason discipline).
# Each maps to a ``t()`` key so the operator-facing string is localized.
_RefusalReason = Literal["unknown_adapter", "missing_secret"]
_REASON_KEY: Final[dict[_RefusalReason, str]] = {
    "unknown_adapter": "gateway.adapter.credential.refused.unknown_adapter",
    "missing_secret": "gateway.adapter.credential.refused.missing_secret",
}

# Per-link dedup-cache bound (ERR-G63-02). The cache is INTERNAL to one core link's
# lifetime, but a restart-storm of distinct ``(adapter_id, host_restart_seq, epoch)``
# triples (e.g. a gateway flapping its ``host_restart_seq``) would grow it without
# limit. Cap it FIFO (oldest-evicted) — the same bound discipline as
# :data:`alfred.comms_mcp.crash_incident_reconciler._MAX_INCIDENTS_PER_ADAPTER`. A
# legitimately re-requested credential past the cap simply re-resolves (a fresh
# broker.get + audit), which is correct: the cache is a decrypt-storm guard, not a
# correctness store.
_MAX_GRANTED_CREDENTIALS: Final[int] = 64


class AdapterCredentialError(AlfredError):
    """A fail-closed credential-resolution / delivery failure (G6-3).

    Rooted at :class:`alfred.errors.AlfredError` (NOT
    :class:`alfred.supervisor.fd3_key_delivery.ProviderKeyDeliveryError`, a different
    subsystem rooted at ``Exception``) so the gateway spawn path can wrap it as
    :class:`alfred.gateway.adapter_supervisor.GatewayAdapterSpawnError` and the
    supervisor's existing crash/breaker arms treat it uniformly.

    Built from ``adapter_id`` + a closed-vocab ``reason`` ONLY — never ``from`` a
    Pydantic ``ValidationError`` carrying the raw input, never with the credential or
    the wire frame in ``args`` (correction C3: the credential is structurally
    un-loggable, including via an exception's ``str()`` / ``repr()`` / ``args``).
    """

    def __init__(self, *, adapter_id: str, reason: str) -> None:
        super().__init__(
            f"adapter credential refused (adapter_id={adapter_id!r}, reason={reason!r})"
        )
        self.adapter_id = adapter_id
        self.reason = reason


class AdapterCredentialAuditWriteError(AlfredError):
    """A signed-audit-write failure while recording a credential grant/refusal (G6-3).

    ERR-G63-01 (#288): the DISTINCT typed marker the resolver raises when an
    ``append_schema`` for a credential GRANT (or a refusal row) fails to persist. It is
    the credential-leg analog of
    :class:`alfred.comms_mcp.adapter_status_observer.AdapterStatusAuditWriteError`, and
    it exists for the SAME reason: a failed signed-audit write that "a real platform
    credential was released" is a NON-skippable security event (CLAUDE.md hard rules
    #5/#7). Without this distinct type the raw backend error (``AuditWriteError`` /
    ``SQLAlchemyError``) would escape ``CoreAdapterCredentialResolver.resolve`` into the
    runner's fire-and-forget ``_route_spawn_request`` dispatch task and surface only as
    a GC-time "Task exception was never retrieved" warning — a SILENT swallow of a
    released-credential audit failure. The live core leg's
    :meth:`alfred.plugins.comms_runner.CommsPluginRunner._route_spawn_request`
    recognises this distinct type and ESCALATES loudly (``log.error`` + a restart
    request) instead of dropping it, mirroring the status-observer SEC-1 arm. The
    resolver NEVER raises this on a bad request (that is the loud audited
    :class:`AdapterCredentialError` refusal) — ONLY on a genuine write failure. The
    credential is NEVER chained into it (the cause is the bare backend error, which
    carries no credential).
    """


class _SecretBrokerLike(Protocol):
    def get(self, name: str) -> str: ...


class _AuditWriterLike(Protocol):
    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, object],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _DedupKey:
    """The canonical ``(adapter_id, host_restart_seq, epoch)`` dedup key (H3)."""

    adapter_id: str
    host_restart_seq: int
    epoch: str


class CoreAdapterCredentialResolver:
    """Resolve a platform credential for one adapter (re)spawn; the only decryptor."""

    def __init__(
        self,
        *,
        broker: _SecretBrokerLike,
        audit: _AuditWriterLike,
        now: Callable[[], datetime],
    ) -> None:
        self._broker = broker
        self._audit = audit
        self._now = now
        # The dedup cache holds the resolved credential keyed on the canonical triple
        # so a true replay returns the SAME grant with the broker called exactly once
        # (H4). The gateway NEVER caches to dedup (it discards a mismatched grant); only
        # the resolver retains, per-core-link lifetime. The credential is held in memory
        # here for the link's lifetime — the same posture as any decrypted secret in the
        # core process; the gateway is the surface G6-3 keeps credential-free.
        #
        # ERR-G63-02: an ``OrderedDict`` so the cache is FIFO-bounded
        # (:data:`_MAX_GRANTED_CREDENTIALS`, oldest-evicted) — a restart-storm of
        # distinct triples cannot grow it without limit. The entry is inserted ONLY
        # AFTER a successful grant+audit (see :meth:`resolve`): an audit-write failure
        # must NEVER poison the dedup cache with an unaudited/undelivered credential.
        self._granted: OrderedDict[_DedupKey, str] = OrderedDict()

    async def resolve(self, request: SpawnRequest) -> SpawnGrant:
        """Resolve ``request`` to a :class:`SpawnGrant`, or raise fail-closed.

        A true replay (same ``(adapter_id, host_restart_seq, epoch)``) returns the
        cached credential, audited ``duplicate=true``, WITHOUT re-decrypting. An
        unknown adapter or a missing secret is a loud, audited refusal.
        """
        key = _DedupKey(
            adapter_id=request.adapter_id,
            host_restart_seq=request.host_restart_seq,
            epoch=request.epoch,
        )
        cached = self._granted.get(key)
        if cached is not None:
            return await self._grant(request, cached, duplicate=True)

        secret_id = _ADAPTER_SECRET_ALLOWLIST.get(request.adapter_id)
        if secret_id is None:
            # Confused-deputy defence: NEVER broker.get(adapter_id). Refuse loud.
            await self._refuse(request, "unknown_adapter")

        try:
            credential = self._broker.get(secret_id)
        except UnknownSecretError:
            # The secret id is allowlisted but not provisioned: fail-closed, no grant.
            # Do NOT chain the broker error — its message could echo the secret name +
            # value shape (C3: the error carries adapter_id + reason only).
            await self._refuse(request, "missing_secret")

        # ERR-G63-02 ordering: resolve secret -> audit (raises -> escalate, NO cache) ->
        # cache -> return. ``_grant`` audits FIRST; only on a SUCCESSFUL grant+audit do
        # we admit the credential to the dedup cache. An
        # ``AdapterCredentialAuditWriteError`` from ``_grant`` propagates here WITHOUT
        # caching, so a subsequent legitimate identical request re-resolves + re-audits
        # (the broker is called again) rather than serving an unaudited credential.
        grant = await self._grant(request, credential, duplicate=False)
        self._granted[key] = credential
        while len(self._granted) > _MAX_GRANTED_CREDENTIALS:
            self._granted.popitem(last=False)
        return grant

    async def _grant(
        self, request: SpawnRequest, credential: str, *, duplicate: bool
    ) -> SpawnGrant:
        grant = SpawnGrant(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            host_restart_seq=request.host_restart_seq,
            epoch=request.epoch,
            credential_material=credential,
        )
        await self._audit_grant(request, duplicate=duplicate)
        return grant

    async def _audit_grant(self, request: SpawnRequest, *, duplicate: bool) -> None:
        occurred_at = self._now().isoformat()
        await self._append_or_raise(
            fields=CORE_ADAPTER_SPAWN_GRANT_FIELDS,
            schema_name="CORE_ADAPTER_SPAWN_GRANT_FIELDS",
            event=CORE_ADAPTER_SPAWN_GRANT,
            subject={
                "adapter_id": request.adapter_id,
                "host_restart_seq": request.host_restart_seq,
                "epoch": request.epoch,
                "occurred_at": occurred_at,
                "result": "granted",
                "duplicate": duplicate,
            },
            result="granted",
            trace_id=request.adapter_id,
        )

    async def _append_or_raise(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, object],
        result: str,
        trace_id: str,
    ) -> None:
        """Write one credential audit row; translate a write failure to the typed marker.

        ERR-G63-01 (#288): both ``append_schema`` sites (a GRANT and a refusal) funnel
        through here so a genuine signed-audit-write failure raises the DISTINCT
        :class:`AdapterCredentialAuditWriteError` (CLAUDE.md hard rules #5/#7 — never a
        silent swallow). The resolver reaches this helper only on a row it has ALREADY
        decided to record (a granted credential or a loud refusal), so any exception
        from ``append_schema`` here is — by the audit writer's contract — a write
        failure, not a decision; wrapping it gives the live core leg a typed handle to
        ESCALATE (the runner's ``_route_spawn_request`` arm) instead of letting the raw
        backend error vanish into the fire-and-forget dispatch task. The credential is
        NEVER chained (the cause is the bare backend error, which carries none).
        """
        try:
            await self._audit.append_schema(
                fields=fields,
                schema_name=schema_name,
                event=event,
                actor_user_id=None,
                subject=subject,
                trust_tier_of_trigger=_CREDENTIAL_TRUST_TIER,
                result=result,
                cost_estimate_usd=0.0,
                trace_id=trace_id,
            )
        except Exception as exc:
            raise AdapterCredentialAuditWriteError(
                f"credential audit write failed for {event!r}"
            ) from exc

    async def _refuse(self, request: SpawnRequest, reason: _RefusalReason) -> NoReturn:
        """Audit a loud refusal then raise :class:`AdapterCredentialError`.

        ``NoReturn`` so the caller's flow knows the credential is bound after the
        non-refusal path. The refusal row uses the SPAWN_REQUEST field-set (the
        request the core observed) with ``result="refused"``; it carries NO
        credential, NO raw frame field. The operator-facing reason is localized via
        :func:`alfred.i18n.t` (the keys are reserved in ``_spec_b_reserve``); the
        EXCEPTION itself carries only ``adapter_id`` + the closed-vocab reason token
        (C3 — no raw input ever in ``args``).
        """
        from alfred.audit.audit_row_schemas import GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS

        occurred_at = self._now().isoformat()
        log.warning(
            "gateway.adapter.credential_refused",
            adapter_id=request.adapter_id,
            reason=reason,
            # Localized operator message (the key is the closed-vocab reason map).
            message=t(_REASON_KEY[reason], adapter_id=request.adapter_id),
        )
        await self._append_or_raise(
            fields=GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS,
            schema_name="GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS",
            event=CORE_ADAPTER_SPAWN_GRANT,
            subject={
                "adapter_id": request.adapter_id,
                "host_restart_seq": request.host_restart_seq,
                "epoch": request.epoch,
                "occurred_at": occurred_at,
                "result": "refused",
            },
            result="refused",
            trace_id=request.adapter_id,
        )
        raise AdapterCredentialError(adapter_id=request.adapter_id, reason=reason)


__all__ = [
    "AdapterCredentialAuditWriteError",
    "AdapterCredentialError",
    "CoreAdapterCredentialResolver",
]
