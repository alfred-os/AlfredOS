"""``AlfredPluginSession`` — manifest handshake + lifecycle audit rows (spec §4.2, §4.6, §4.7).

The session owns the lifecycle of a single plugin subprocess: parse the
manifest, check the capability gate at handshake time, emit the
appropriate ``plugin.lifecycle.*`` audit row at each transition, and
quarantine the subprocess (SIGKILL via :meth:`StdioTransport.kill`) when
a disallowed post-handshake JSON-RPC method arrives.

Why an async classmethod factory (``create()``)
-----------------------------------------------

The manifest parse can raise ``ManifestVersionError`` / ``ManifestTierError``
*before* the session object exists, and the security contract requires a
``plugin.lifecycle.load_refused`` audit row in that case. The audit
writer's ``append_schema`` is ``async def`` (PR-S3-0a, Cluster 4
invariant), so the emit must be awaited — but ``__init__`` cannot
``await``. The fix (rvw-cr-round-1) splits construction into:

* a synchronous ``__init__`` taking an already-parsed
  :class:`PluginManifest` — pure state, no I/O.
* an ``async classmethod create()`` that handles parsing + the awaited
  load-refused emit on failure + final construction.

All call sites — production and tests — use
``await AlfredPluginSession.create(manifest_raw=..., audit_writer=..., gate=...)``.
Direct ``__init__`` construction is internal and skips the load_refused
emit, which is a security-relevant invariant; the docstring marks it
explicitly so an unwitting caller is warned at the type level.

SIGKILL ordering on post-handshake hook-register attack
------------------------------------------------------

Spec §4.6: a plugin sending ``alfred/hooks.register`` after the manifest
handshake is trying to silently install a hook subscription — a tier-
laundering attack vector. Defence is to:

1. ``await transport.kill()`` BEFORE the audit row is written. The row
   says ``signal='SIGKILL'`` only if the kill actually landed; making
   the claim true at write time means an operator cannot be lied to by
   a misbehaving subprocess that races between the decision and the
   syscall (sec-013 / core-007 fix).
2. Emit ``plugin.lifecycle.quarantined`` in a ``try/finally`` so the
   operator sees the quarantine event even when the kill itself fails
   (rvw-pre-flight fix). The ``kill_succeeded`` field on the row
   reflects the actual outcome — operators reading the audit log can
   distinguish "kill landed" from "kill failed but quarantine intent
   was logged".

err-017: best-effort plugin_id extraction
-----------------------------------------

When the strict parse fails, the audit row still needs a forensic id so
operators can correlate it back to the failing manifest blob. The
session scans the raw TOML for an ``id = "..."`` token; if present, the
row carries that string. If not, a stable sha256-prefix sentinel
(``unknown(sha256=...)``) goes in instead. Both are closed-vocabulary
safe-for-audit (spec §5.6).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas
from alfred.audit.log import AuditWriter
from alfred.comms_mcp import observability as comms_observability
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_STATUS_PREFIX
from alfred.hooks.capability import CapabilityGate
from alfred.plugins.errors import (
    ManifestError,
    PluginError,
    SandboxInfoHandshakeMismatch,
)
from alfred.plugins.manifest import PluginManifest, parse_manifest
from alfred.security.dlp import redact_secret_shapes
from alfred.utils.sliding_window_counter import SlidingWindowCounter

if TYPE_CHECKING:
    from alfred.comms_mcp.handlers import (
        BindingHandler,
        CrashHandler,
        InboundHandler,
        RateLimitHandler,
    )
    from alfred.plugins.stdio_transport import StdioTransport

log = structlog.get_logger(__name__)

# Spec §4.6: methods a plugin MUST NOT send post-handshake. The host is
# the sole authority for hook registration; a plugin asking to register
# one is a quarantine trigger.
_DISALLOWED_POST_HANDSHAKE_METHODS: Final[frozenset[str]] = frozenset(
    {
        "alfred/hooks.register",
    }
)

# Used by ``_best_effort_plugin_id`` to scrape the [plugin] id field from
# a manifest blob whose strict parse failed. The regex deliberately does
# NOT validate section structure — it accepts a bare ``id = "..."``
# anywhere in the file, because by definition the parse already failed.
_PLUGIN_ID_RE: Final[re.Pattern[str]] = re.compile(r'\bid\s*=\s*"([^"]+)"')


def _best_effort_plugin_id(manifest_raw: str) -> str:
    """Extract a forensically-useful plugin id from a failed-parse manifest.

    Returns the ``[plugin] id`` value if it is recoverable from the raw
    TOML (matched by ``_PLUGIN_ID_RE`` without strict section parsing),
    else a sha256-prefix sentinel of the form
    ``unknown(sha256=<first-12-hex>)`` so the failed manifest stays
    identifiable across the audit log.

    Neither return value carries T3 content: ``id`` is a closed-
    vocabulary plugin slug; sha256-of-bytes is a hash digest. Both are
    spec §5.6-safe.
    """
    match = _PLUGIN_ID_RE.search(manifest_raw)
    if match:
        return match.group(1)
    digest = hashlib.sha256(manifest_raw.encode()).hexdigest()[:12]
    return f"unknown(sha256={digest})"


# Audit-emit shared constants. ``cost_estimate_usd=0.0`` because lifecycle
# rows do not have a per-row cost (they record control-plane events, not
# LLM calls). ``actor_user_id=None`` because the session acts on behalf
# of the host process, not a specific user — the supervisor authoring
# this row is system-level (T0). ``trust_tier_of_trigger="T0"`` for the
# same reason: the handshake is internal control-plane state.
_AUDIT_TRUST_TIER: Final[str] = "T0"
_AUDIT_COST_USD: Final[float] = 0.0

# ---------------------------------------------------------------------------
# PR-S4-8 comms-notification dispatch (Component G, Tasks 35-42).
# ---------------------------------------------------------------------------

# The four plugin -> host notification methods the dispatch arm fans out to
# (spec §8.4). A post-handshake method NOT in this set (and not a Slice-3
# disallowed/sandbox method) is an unknown notification: audited + restart-
# requested, never silently dropped.
_COMMS_NOTIFICATION_METHODS: Final[frozenset[str]] = frozenset(
    {
        "inbound.message",
        "adapter.binding_request",
        "adapter.rate_limit_signal",
        "adapter.crashed",
    }
)

# err-007: three handler failures inside this window trips the adapter's
# circuit breaker. Mirrors the Slice-3 CircuitBreaker failure window so a
# comms-handler storm and a plugin-crash storm trip on the same cadence.
_HANDLER_FAILURE_THRESHOLD: Final[int] = 3
_HANDLER_FAILURE_WINDOW: Final[timedelta] = timedelta(minutes=5)

# Bound on the redacted exception detail carried into COMMS_HANDLER_FAILED_FIELDS
# (spec §8.4 pseudocode — str(exc) truncated then DLP-scanned).
_HANDLER_DETAIL_MAX_LEN: Final[int] = 512

# Closed-vocab handler-failure bucket. The open-vocab Python exception type
# lands on ``error_class``; ``reason`` is the SLO bucket. The dispatcher cannot
# know the semantic cause of an arbitrary handler exception, so it records the
# generic bucket — finer buckets are the handlers' own concern.
_HANDLER_FAILURE_REASON: Final[str] = "handler_exception"

# Closed-vocab handler-class label per notification method, for the
# ``handler_class`` field on COMMS_HANDLER_FAILED_FIELDS. A stable label (not
# ``type(handler).__name__``) so the audit field stays meaningful regardless of
# which concrete handler / test double is wired.
_HANDLER_CLASS_BY_METHOD: Final[Mapping[str, str]] = {
    "inbound.message": "InboundHandler",
    "adapter.binding_request": "BindingHandler",
    "adapter.rate_limit_signal": "RateLimitHandler",
    "adapter.crashed": "CrashHandler",
}


def _redact_value(value: object) -> object:
    """Recursively scrub secret-shaped tokens from any string at any depth.

    A plugin-supplied (T3-shaped) param can nest a credential inside a dict,
    list, or tuple; a top-level-only scrub would leak it. This walks every
    container and applies :func:`redact_secret_shapes` to every string found,
    leaving non-string leaves untouched. ``Mapping``/``Sequence`` are matched
    structurally so arbitrary JSON-shaped payloads are covered; ``str`` and
    ``bytes`` are deliberately excluded from the sequence branch (a ``str`` is a
    sequence of ``str`` and would otherwise recurse forever).
    """
    if isinstance(value, str):
        return redact_secret_shapes(value)
    if isinstance(value, Mapping):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact_params(params: Mapping[str, object] | None) -> Mapping[str, object]:
    """Scrub secret-shaped tokens from every string value of a params dict.

    Critical 6: an unknown-method payload is plugin-supplied (T3-shaped); a
    credential smuggled in a string value — at any nesting depth — is redacted
    before it reaches the ``method_redacted_params`` audit field. Non-string
    leaves pass through unchanged (they cannot carry a secret-shaped token).
    ``None`` → empty dict.
    """
    if params is None:
        return {}
    return {key: _redact_value(value) for key, value in params.items()}


# Mirrors ``Settings.comms_max_in_flight_notifications`` default (config field
# ``Field(default=32, ge=1, le=1024)``). The factory takes the cap as a plain
# int so it stays pure + unit-testable; the daemon passes the live setting.
_DEFAULT_MAX_IN_FLIGHT: Final[int] = 32


@runtime_checkable
class _SupervisorLike(Protocol):
    """Narrow structural seam for the supervisor the dispatcher escalates to.

    The session depends on this Protocol rather than the concrete
    :class:`alfred.supervisor.core.Supervisor` to avoid a module-import cycle
    (``alfred.supervisor`` already imports ``alfred.plugins.errors``). The two
    methods are the only supervisor surface the dispatch arm touches.
    """

    async def trip_breaker(self, *, component_id: str, reason: str) -> None: ...

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None: ...


@runtime_checkable
class _StatusObserverLike(Protocol):
    """Narrow structural seam for the gateway-adapter-status observer (Spec B G6-2b-2a).

    The session routes every ``gateway.adapter.*`` frame here. The concrete type is
    :class:`alfred.comms_mcp.adapter_status_observer.AdapterStatusObserver`; the session
    depends on this Protocol so it does not import the comms-MCP observer concretely. The
    observer NEVER raises on a bad/forged frame (it audits a loud refusal); the ONLY
    raise path is a genuine signed-audit-write failure (a typed
    ``AdapterStatusAuditWriteError``), which the arm lets propagate so the live
    fire-and-forget runner can ESCALATE it (loud ``log.error`` + restart request),
    NOT swallow it (SEC-1).
    """

    async def observe(self, method: object, params: object) -> None: ...


class _NoopSemaphore:
    """An async-context-manager no-op standing in for the dispatch semaphore.

    Slice-3 callers never enter the comms dispatch arm (they only hit the
    disallowed-method / sandbox_info paths), so they get this no-op instead of
    a real :class:`asyncio.BoundedSemaphore`. The enforcing
    :meth:`AlfredPluginSession.for_comms_adapter` factory always allocates a
    real per-session semaphore.
    """

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


class AlfredPluginSession:
    """Owns the lifecycle of a single plugin subprocess (spec §4.2, §4.6, §4.7).

    Public construction is via :meth:`create`. The synchronous
    ``__init__`` is internal — it takes an already-parsed
    :class:`PluginManifest` and skips the
    ``plugin.lifecycle.load_refused`` emit on manifest failure, which is
    a security-relevant invariant. Calling ``__init__`` directly without
    going through ``create()`` is documented as "internal".

    The ``_handshake_complete`` flag pins the post-handshake message-
    routing transition: ``_on_post_handshake_method`` is the only entry
    point that consults it, and it is set ``True`` exactly once by
    ``_on_handshake_complete`` on success.
    """

    def __init__(
        self,
        *,
        manifest: PluginManifest,
        audit_writer: AuditWriter,
        gate: CapabilityGate,
        transport: StdioTransport | None = None,
        correlation_id: str | None = None,
        # PR-S4-8 comms params (Component G, Task 35). All default to ``None``
        # so every Slice-3 caller (which never enters the comms dispatch arm)
        # constructs unchanged. The enforcing ``for_comms_adapter`` factory
        # makes the four handlers required + allocates a real per-session
        # semaphore + error counter.
        adapter_id: str | None = None,
        inbound_handler: InboundHandler | None = None,
        binding_handler: BindingHandler | None = None,
        rate_limit_handler: RateLimitHandler | None = None,
        crash_handler: CrashHandler | None = None,
        supervisor: _SupervisorLike | None = None,
        status_observer: _StatusObserverLike | None = None,
        dispatch_semaphore: asyncio.BoundedSemaphore | _NoopSemaphore | None = None,
        error_counter: SlidingWindowCounter | None = None,
    ) -> None:
        """Internal: prefer ``await AlfredPluginSession.create(manifest_raw=...)``.

        Takes an already-parsed :class:`PluginManifest` so this is pure
        synchronous state init — no audit emits, no I/O. The
        :meth:`create` factory handles the parse and the awaited
        ``plugin.lifecycle.load_refused`` emit on failure.

        The comms params default to ``None`` (Slice-3 back-compat). When a
        comms adapter is wired, prefer :meth:`for_comms_adapter` — it makes
        the four handlers required and allocates the per-session dispatch
        state. ``dispatch_semaphore`` defaults to a :class:`_NoopSemaphore`
        so the Slice-3 disallowed-method path constructs without a real one.
        """
        self._audit_writer = audit_writer
        self._gate = gate
        self._transport = transport
        self._manifest: PluginManifest = manifest
        self._handshake_complete = False
        self._correlation_id = correlation_id or str(uuid.uuid4())

        self._adapter_id = adapter_id
        self._inbound_handler = inbound_handler
        self._binding_handler = binding_handler
        self._rate_limit_handler = rate_limit_handler
        self._crash_handler = crash_handler
        self._supervisor = supervisor
        # Spec B G6-2b-2a (#288): the core-side gateway-adapter-status observer. Injected
        # into every comms session by the daemon boot graph (correction #8 — ALL comms
        # sessions, not just a gateway leg), so a ``gateway.adapter.*`` frame is routed to
        # it BEFORE the comms-notification dispatch + the unknown-method tail.
        self._status_observer = status_observer
        self._dispatch_semaphore: asyncio.BoundedSemaphore | _NoopSemaphore = (
            dispatch_semaphore if dispatch_semaphore is not None else _NoopSemaphore()
        )
        self._error_counter: SlidingWindowCounter = (
            error_counter if error_counter is not None else SlidingWindowCounter()
        )

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        *,
        manifest_raw: str,
        audit_writer: AuditWriter,
        gate: CapabilityGate,
        transport: StdioTransport | None = None,
    ) -> AlfredPluginSession:
        """Parse the manifest, emit load_refused on failure, then construct.

        The awaited ``audit_writer.append_schema(...)`` on manifest
        rejection is the load-bearing reason this factory is async. A
        synchronous ``__init__`` would silently drop the coroutine,
        omitting the audit row for a tier-laundering attempt — see
        rvw-cr-round-1.

        Catches every :class:`ManifestError` subclass (not just version
        / tier). CR on PR #140 caught the prior narrower handler as a
        contract gap: ``parse_manifest`` also raises plain
        :class:`ManifestError` for malformed TOML, missing ``[plugin]``
        table, missing/invalid id, unknown subscriber_tier label, and
        wrong types for ``sandbox_profile`` / ``platform``. Those
        paths previously propagated with NO ``plugin.lifecycle.load_refused``
        row, violating the refused-load audit contract in PRD §4.2 — an
        operator could not distinguish "we never received the manifest"
        from "we received it and refused it for shape reasons". The
        emit helper handles the version-less / tier-less subclass via
        ``getattr(exc, "got", -1)`` so this broader catch is safe.
        """
        correlation_id = str(uuid.uuid4())
        try:
            manifest = parse_manifest(manifest_raw)
        except ManifestError as exc:
            await cls._emit_load_refused_from_parse_failure(
                audit_writer=audit_writer,
                manifest_raw=manifest_raw,
                exc=exc,
                correlation_id=correlation_id,
            )
            raise
        return cls(
            manifest=manifest,
            audit_writer=audit_writer,
            gate=gate,
            transport=transport,
            correlation_id=correlation_id,
        )

    @classmethod
    async def for_comms_adapter(
        cls,
        *,
        adapter_id: str,
        manifest_raw: str,
        audit_writer: AuditWriter,
        gate: CapabilityGate,
        supervisor: _SupervisorLike,
        inbound_handler: InboundHandler,
        binding_handler: BindingHandler,
        rate_limit_handler: RateLimitHandler,
        crash_handler: CrashHandler,
        status_observer: _StatusObserverLike | None = None,
        transport: StdioTransport | None = None,
        max_in_flight_notifications: int = _DEFAULT_MAX_IN_FLIGHT,
    ) -> AlfredPluginSession:
        """Enforcing factory for a comms-adapter session (comms-004).

        Unlike :meth:`create`, all four notification handlers are **required**
        keyword arguments — a comms adapter cannot be spawned with a missing
        handler (no Optional, no ``_NoopSemaphore`` default for the dispatch
        arm). PR-S4-9 / PR-S4-10 adapter launchers MUST go through this
        factory; the Slice-3 ``__init__`` keeps the Optional kwargs only for
        in-process back-compat.

        Allocates a **fresh per-session** :class:`asyncio.BoundedSemaphore`
        (perf-003: per-adapter, never process-wide, so one adapter's storm
        cannot starve another) and a fresh :class:`SlidingWindowCounter` for
        the err-007 breaker trigger. ``max_in_flight_notifications`` caps the
        semaphore; the daemon boot path passes
        ``Settings.comms_max_in_flight_notifications`` (the factory takes it as
        a plain int so it stays pure + unit-testable without an env load).

        Reuses :meth:`create`'s manifest parse + load-refused audit path, then
        rebinds the parsed manifest with the comms wiring.
        """
        base = await cls.create(
            manifest_raw=manifest_raw,
            audit_writer=audit_writer,
            gate=gate,
            transport=transport,
        )
        return cls(
            manifest=base._manifest,
            audit_writer=audit_writer,
            gate=gate,
            transport=transport,
            correlation_id=base._correlation_id,
            adapter_id=adapter_id,
            inbound_handler=inbound_handler,
            binding_handler=binding_handler,
            rate_limit_handler=rate_limit_handler,
            crash_handler=crash_handler,
            supervisor=supervisor,
            status_observer=status_observer,
            dispatch_semaphore=asyncio.BoundedSemaphore(value=max_in_flight_notifications),
            error_counter=SlidingWindowCounter(),
        )

    @staticmethod
    async def _emit_load_refused_from_parse_failure(
        *,
        audit_writer: AuditWriter,
        manifest_raw: str,
        exc: ManifestError,
        correlation_id: str,
    ) -> None:
        """Write the ``plugin.lifecycle.load_refused`` row for a parse-time failure.

        Separated into a static method so the failure-emit path is
        independently testable and the ``create()`` body stays small.
        """
        best_effort_id = _best_effort_plugin_id(manifest_raw)
        # ``got`` on ManifestVersionError is always an int (-1 sentinel
        # for "source value was not even an int"); ManifestTierError has
        # no version field — record -1 in that case so the row remains
        # symmetric with the schema.
        manifest_version_value = getattr(exc, "got", -1)
        log.error(
            "plugin_load_refused_parse_failure",
            plugin_id=best_effort_id,
            exception_type=type(exc).__name__,
            correlation_id=correlation_id,
        )
        await audit_writer.append_schema(
            fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
            schema_name="PLUGIN_LIFECYCLE_FIELDS",
            event="plugin.lifecycle.load_refused",
            actor_user_id=None,
            subject={
                "plugin_id": best_effort_id,
                "manifest_subscriber_tier": "unknown",
                "manifest_version": manifest_version_value,
                "sandbox_profile": "unknown",
                "exit_code": None,
                "signal": None,
                "restart_count": 0,
                "breaker_state": "CLOSED",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="refused",
            cost_estimate_usd=_AUDIT_COST_USD,
            trace_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Handshake-complete transition
    # ------------------------------------------------------------------

    async def _on_handshake_complete(self) -> None:
        """Run the gate check + emit ``plugin.lifecycle.loaded`` on success.

        Idempotent: a second call after a successful first call is a
        no-op (no second ``loaded`` row, no second gate consultation).
        This protects the supervisor against accidentally double-logging
        ``loaded`` if a handshake-driving code path retries.

        On gate denial: emit ``plugin.lifecycle.load_refused`` then
        raise :class:`PluginError` so the supervisor unwinds the
        subprocess. The row lands before the raise.
        """
        if self._handshake_complete:
            return

        if not self._gate.check_plugin_load(
            plugin_id=self._manifest.plugin_id,
            manifest_tier=self._manifest.subscriber_tier,
        ):
            log.error(
                "plugin_load_refused_gate",
                plugin_id=self._manifest.plugin_id,
                manifest_tier=self._manifest.subscriber_tier,
                correlation_id=self._correlation_id,
            )
            await self._audit_writer.append_schema(
                fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
                schema_name="PLUGIN_LIFECYCLE_FIELDS",
                event="plugin.lifecycle.load_refused",
                actor_user_id=None,
                subject={
                    "plugin_id": self._manifest.plugin_id,
                    "manifest_subscriber_tier": self._manifest.subscriber_tier,
                    "manifest_version": self._manifest.manifest_version,
                    "sandbox_profile": self._manifest.sandbox_profile,
                    "exit_code": None,
                    "signal": None,
                    "restart_count": 0,
                    "breaker_state": "CLOSED",
                    "correlation_id": self._correlation_id,
                },
                trust_tier_of_trigger=_AUDIT_TRUST_TIER,
                result="refused",
                cost_estimate_usd=_AUDIT_COST_USD,
                trace_id=self._correlation_id,
            )
            raise PluginError(f"capability gate denied load for {self._manifest.plugin_id!r}")

        self._handshake_complete = True
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
            schema_name="PLUGIN_LIFECYCLE_FIELDS",
            event="plugin.lifecycle.loaded",
            actor_user_id=None,
            subject={
                "plugin_id": self._manifest.plugin_id,
                "manifest_subscriber_tier": self._manifest.subscriber_tier,
                "manifest_version": self._manifest.manifest_version,
                "sandbox_profile": self._manifest.sandbox_profile,
                "exit_code": None,
                "signal": None,
                "restart_count": 0,
                "breaker_state": "CLOSED",
                "correlation_id": self._correlation_id,
            },
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="allowed",
            cost_estimate_usd=_AUDIT_COST_USD,
            trace_id=self._correlation_id,
        )

    # ------------------------------------------------------------------
    # Post-handshake message routing
    # ------------------------------------------------------------------

    async def _on_post_handshake_method(
        self,
        method: str,
        params: Mapping[str, object] | None = None,
        *,
        wire_seq: int | None = None,
    ) -> None:
        """Route a post-handshake JSON-RPC method through the security gate.

        Two refusal shapes:

        * Methods in :data:`_DISALLOWED_POST_HANDSHAKE_METHODS` (spec §4.6:
          currently ``alfred/hooks.register``) — the host is the sole
          authority for hook registration; a plugin asking to register one is
          quarantined.
        * ``sandbox_info`` (PR-S4-6 arch-3) whose reported
          ``effective_sandbox_kind`` disagrees with the manifest's declared
          ``sandbox.kind`` — a plugin lying about its own containment. The
          mismatch is quarantined AND re-raised as
          :class:`SandboxInfoHandshakeMismatch` so the supervisor's spawn
          path refuses the session.

        Either refusal tears the session down: SIGKILL the subprocess BEFORE
        the audit row writes (so a ``signal='SIGKILL'`` claim is only made
        when the kill landed — sec-013 / core-007), then emit
        ``plugin.lifecycle.quarantined`` in a ``try/finally`` so the row
        lands regardless of kill outcome (rvw-pre-flight).

        PR-S4-8 dispatch arm (Component G). A method in
        :data:`_COMMS_NOTIFICATION_METHODS` is validated against its wire
        schema and fanned out to the matching handler, the whole block wrapped
        in ``async with self._dispatch_semaphore`` (per-adapter; perf-003). A
        handler exception emits ``COMMS_HANDLER_FAILED_FIELDS`` + increments
        the error counter + trips the breaker on 3 failures in 5min, then
        **re-raises** (err-007 — loud; the original exception propagates to the
        StdioTransport reader, which logs + continues). An *unknown* method
        emits ``COMMS_UNKNOWN_NOTIFICATION_FIELDS`` + requests a plugin restart
        and does NOT raise.
        """
        if method == "sandbox_info":
            await self._verify_sandbox_info(params)
            return
        if method in _DISALLOWED_POST_HANDSHAKE_METHODS:
            log.error(
                "post_handshake_disallowed_method",
                plugin_id=self._manifest.plugin_id,
                method=method,
                correlation_id=self._correlation_id,
            )
            await self._quarantine_teardown(reason_base="protocol_violation")
            return

        # Spec B G6-2b-2a (#288), corrections #2 + SEC-2: a gateway-reported
        # adapter-status frame (``gateway.adapter.*``). Routed to the
        # AdapterStatusObserver (validate -> epoch-reconcile -> audit -> refuse forged),
        # NOT the comms-notification handler fan-out and NOT the T3 inbound pipeline.
        # Evaluated BEFORE the ``not _is_comms_session`` early return so the observer is
        # the SOLE authority over the WHOLE ``gateway.adapter.*`` namespace regardless of
        # session type — a forged ``gateway.adapter.bogus`` hits the observer's
        # ``unknown_method`` refusal (audited ``status_rejected``), never the generic
        # unknown-method handler that would restart the leg. The ``and`` short-circuits so
        # ``_route_...`` is called ONLY for the prefix; it returns True when the observer
        # consumed the frame. With NO observer wired (defensive — production always injects
        # one) it returns False and we FALL THROUGH to the shared unknown-method tail below
        # (non-comms: no-op; comms: loud unknown + restart) — one covered path, no
        # duplicated tail.
        if method.startswith(
            GATEWAY_ADAPTER_STATUS_PREFIX
        ) and await self._route_gateway_adapter_status(method, params):
            return

        # Slice-3 in-process sessions (no comms wiring) keep the legacy no-op
        # tail: a non-disallowed, non-sandbox method (e.g. ``lifecycle.stop``)
        # is routed elsewhere by the supervisor and is not this session's
        # concern. Only a comms-wired session (built via ``for_comms_adapter``,
        # i.e. ``adapter_id`` set) owns the comms dispatch + unknown-method
        # contract (Critical 6).
        if not self._is_comms_session:
            return

        if method in _COMMS_NOTIFICATION_METHODS:
            await self._dispatch_comms_notification(method, params, wire_seq=wire_seq)
            return

        # Unknown post-handshake method on a comms session — not silently
        # dropped (Critical 6): typed audit row first, then restart request.
        await self._emit_unknown_notification(method, params)
        if self._supervisor is not None:
            await self._supervisor.request_plugin_restart(
                adapter_id=self._effective_adapter_id, reason="unknown_notification"
            )

    @property
    def _is_comms_session(self) -> bool:
        """True when this session was wired as a comms adapter.

        A comms session is constructed with an explicit ``adapter_id`` (always
        set by :meth:`for_comms_adapter`; never by a Slice-3 in-process
        caller). Only a comms session owns the comms-notification dispatch +
        unknown-method contract — a Slice-3 session keeps the legacy no-op
        tail for any non-disallowed, non-sandbox method.
        """
        return self._adapter_id is not None

    @property
    def _effective_adapter_id(self) -> str:
        """The adapter id for audit/supervisor calls on a comms session.

        Only reached from the comms dispatch / unknown-method paths, which are
        gated on :attr:`_is_comms_session` (``adapter_id`` set). The assert
        pins that invariant for the type checker and fails loudly if a future
        refactor reaches here on a Slice-3 session.
        """
        assert self._adapter_id is not None
        return self._adapter_id

    async def _dispatch_comms_notification(
        self, method: str, params: Mapping[str, object] | None, *, wire_seq: int | None = None
    ) -> None:
        """Validate + fan a comms notification to its handler under the semaphore.

        ``wire_seq`` (Spec A G4b-2a-pre / ADR-0032) is THIS frame's out-of-band wire
        seq, forwarded to :meth:`_route_comms_notification` where the
        ``inbound.message`` arm merges it into the model so it reaches
        ``model_validate`` bound to its own frame (F1); ``None`` for stdio.

        ``async with self._dispatch_semaphore`` (not ``acquire``/``release``)
        guarantees the slot is released on the exception path (core-008). The
        semaphore is per-adapter (perf-003): one adapter's notification storm
        applies backpressure into its own stdio reader, never starving a
        sibling adapter.

        On a handler exception the audit row + counter increment + (conditional)
        breaker trip happen BEFORE the ``raise`` — the original exception still
        propagates to the StdioTransport reader, which logs + continues to the
        next frame (err-007 / catch-and-continue invariant).
        """
        async with self._dispatch_semaphore:
            started = time.monotonic()
            try:
                await self._route_comms_notification(method, params, wire_seq=wire_seq)
            except Exception as exc:
                # Task 62: one increment per COMMS_HANDLER_FAILED_FIELDS emit,
                # observed on the same loud failure path (err-007).
                comms_observability.record_handler_failure()
                # L1 (error reviewer): if the audit write itself fails, the
                # original handler exception must not be lost. Chain it as the
                # cause so the forensic trail keeps both the handler failure
                # (the real fault) and the audit-write failure (the secondary).
                try:
                    await self._emit_handler_failed(method, exc)
                except Exception as audit_exc:
                    raise exc from audit_exc
                self._error_counter.increment()
                if (
                    self._error_counter.exceeds(
                        threshold=_HANDLER_FAILURE_THRESHOLD, window=_HANDLER_FAILURE_WINDOW
                    )
                    and self._supervisor is not None
                ):
                    await self._supervisor.trip_breaker(
                        component_id=self._effective_adapter_id,
                        reason="comms_handler_repeated_failures",
                    )
                raise
            finally:
                # Task 62: dispatch wall time on every outcome (success OR the
                # err-007 re-raise path) so the p99 reflects the full call.
                comms_observability.record_inbound_dispatch_seconds(time.monotonic() - started)

    async def _route_comms_notification(
        self, method: str, params: Mapping[str, object] | None, *, wire_seq: int | None = None
    ) -> None:
        """Validate ``params`` against the wire schema + await the one handler.

        Handlers are awaited sequentially per notification — a single
        notification never fans out to two handlers concurrently (spec §8.4
        last paragraph; perf-003 clarification). Concurrency across
        notifications is bounded only by the dispatch semaphore.

        ``wire_seq`` (Spec A G4b-2a-pre / ADR-0032 — F1) is merged into the
        ``inbound.message`` model at ``model_validate`` so the host durable-intake
        ack tracker sees the seq BOUND TO THIS FRAME. It is merged ONLY for
        ``inbound.message`` (the only notification carrying ``wire_seq``); the other
        three arms ignore it. When ``None`` (stdio / un-sequenced) nothing is merged,
        so the model defaults ``wire_seq`` to ``None`` and the dispatch is
        byte-for-byte unchanged from the pre-G4b path.
        """
        from alfred.comms_mcp.protocol import (
            BindingRequestNotification,
            CrashedNotification,
            InboundMessageNotification,
            RateLimitSignal,
        )

        raw = dict(params) if params is not None else {}
        match method:
            case "inbound.message":
                assert self._inbound_handler is not None
                # Bind the seq to THIS frame's model — the HOST is authoritative.
                # Set it UNCONDITIONALLY (even to ``None``): ``wire_seq`` is carrier
                # header metadata, NEVER payload-derived (ADR-0032), so a peer that
                # smuggles a ``"wire_seq"`` into ``params`` must NOT reach the host ack
                # tracker. On an un-sequenced (mixed-wire) socket unit the host folds
                # ``None``, which here actively CLEARS any smuggled value. ``raw`` is a
                # per-call dict (a fresh copy of ``params``), never shared — no
                # cross-frame bleed even under concurrent dispatch.
                raw["wire_seq"] = wire_seq
                await self._inbound_handler.process(InboundMessageNotification.model_validate(raw))
            case "adapter.binding_request":
                assert self._binding_handler is not None
                await self._binding_handler.process(BindingRequestNotification.model_validate(raw))
            case "adapter.rate_limit_signal":
                assert self._rate_limit_handler is not None
                await self._rate_limit_handler.process(RateLimitSignal.model_validate(raw))
            case "adapter.crashed":
                assert self._crash_handler is not None
                await self._crash_handler.process(CrashedNotification.model_validate(raw))
            case _:
                # Unreachable in normal flow — ``_COMMS_NOTIFICATION_METHODS``
                # gates this router upstream. Defence-in-depth: fail fast with a
                # clear error naming the method rather than silently coercing an
                # unhandled method into ``adapter.crashed`` (CR finding 2).
                raise PluginError(
                    f"_route_comms_notification reached an unhandled method: {method!r}"
                )

    async def _emit_handler_failed(self, method: str, exc: Exception) -> None:
        """Write the ``COMMS_HANDLER_FAILED_FIELDS`` row for a handler exception.

        ``detail_redacted`` is ``str(exc)`` scrubbed of secret-shaped tokens
        (:func:`redact_secret_shapes`) then truncated to
        :data:`_HANDLER_DETAIL_MAX_LEN` — so a downstream-broke message that
        echoes a credential never reaches the audit log (CLAUDE.md hard rule 1).
        ``error_class`` is the open-vocab Python type name; ``reason`` is the
        closed-vocab SLO bucket.
        """
        detail = redact_secret_shapes(str(exc))[:_HANDLER_DETAIL_MAX_LEN]
        log.error(
            "comms.handler_failed",
            plugin_id=self._effective_adapter_id,
            notification_method=method,
            error_class=type(exc).__name__,
            correlation_id=self._correlation_id,
        )
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_HANDLER_FAILED_FIELDS,
            schema_name="COMMS_HANDLER_FAILED_FIELDS",
            event="comms.handler.failed",
            actor_user_id=None,
            subject={
                "adapter_id": self._effective_adapter_id,
                "notification_method": method,
                "handler_class": _HANDLER_CLASS_BY_METHOD[method],
                "error_class": type(exc).__name__,
                "reason": _HANDLER_FAILURE_REASON,
                "detail_redacted": detail,
                "failed_at": datetime.now(UTC).isoformat(),
            },
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="failed",
            cost_estimate_usd=_AUDIT_COST_USD,
            trace_id=self._correlation_id,
        )

    async def _route_gateway_adapter_status(
        self, method: str, params: Mapping[str, object] | None
    ) -> bool:
        """Hand one ``gateway.adapter.*`` frame to the injected status observer.

        Spec B G6-2b-2a (#288). The observer validates / epoch-reconciles / audits /
        refuses — it NEVER raises on a bad or forged frame (a loud audited refusal is
        not an exception). The ONLY exception it raises is a genuine signed-audit-write
        failure (the typed :class:`AdapterStatusAuditWriteError`); this method does NOT
        catch it (SEC-1) — it must propagate so the live runner's
        :meth:`alfred.plugins.comms_runner.CommsPluginRunner._route_notification`
        recognises it past its blanket catch-and-continue and ESCALATES it loudly
        (``log.error`` + restart request — NOT a re-raise, since the runner only ever
        runs this fire-and-forget; CLAUDE.md hard rules #5/#7).

        Returns ``True`` when an observer consumed the frame, ``False`` when NO observer
        is wired (a non-gateway leg, or a Slice-3 session that somehow received the
        method). On ``False`` the caller falls through to the shared unknown-method tail
        in :meth:`_on_post_handshake_method`, which handles it uniformly: a non-comms
        session no-ops it (like any other Slice-3 method), a comms session emits the loud
        audited unknown row + requests a restart — never silently dropped (hard rule #7).
        Correction #8 documents that in production the observer is injected into EVERY
        comms session, so the ``False`` path is defensive. Delegating to the single shared
        tail (rather than duplicating it here) keeps one covered code path and avoids an
        ``_effective_adapter_id`` assert on a non-comms session.
        """
        if self._status_observer is not None:
            await self._status_observer.observe(method, params)
            return True
        return False

    async def _emit_unknown_notification(
        self, method: str, params: Mapping[str, object] | None
    ) -> None:
        """Write the ``COMMS_UNKNOWN_NOTIFICATION_FIELDS`` row (Critical 6).

        The unknown method is NOT silently dropped. ``method_redacted_params``
        applies :func:`redact_secret_shapes` to every string value in the
        params dict so a credential smuggled in an unknown-method payload never
        reaches the audit log.
        """
        log.warning(
            "comms.unknown_notification",
            plugin_id=self._effective_adapter_id,
            method=method,
            correlation_id=self._correlation_id,
        )
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_UNKNOWN_NOTIFICATION_FIELDS,
            schema_name="COMMS_UNKNOWN_NOTIFICATION_FIELDS",
            event="comms.unknown.notification",
            actor_user_id=None,
            subject={
                "adapter_id": self._effective_adapter_id,
                "method": method,
                "method_redacted_params": _redact_params(params),
                "observed_at": datetime.now(UTC).isoformat(),
            },
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="refused",
            cost_estimate_usd=_AUDIT_COST_USD,
            trace_id=self._correlation_id,
        )

    async def _verify_sandbox_info(self, params: object) -> None:
        """Compare the plugin-reported sandbox kind against the manifest (arch-3).

        A missing or mismatched ``effective_sandbox_kind`` is a plugin that
        will not (or cannot) honestly attest its isolation — quarantine the
        session and re-raise :class:`SandboxInfoHandshakeMismatch`.

        ``params`` is untrusted plugin-supplied JSON, so it is NOT assumed to
        be an object (sec / CR #229 R2 finding-3). A non-``dict`` ``params``
        (a list/string/number, or ``None``) is treated as a lie: a plugin that
        cannot supply a well-formed attestation object is refused exactly like
        one whose ``effective_sandbox_kind`` mismatches — fail-closed (hard
        rule #7), never an ``AttributeError`` before quarantine/audit.
        """
        declared = self._manifest.sandbox.kind
        if isinstance(params, dict):
            reported = params.get("effective_sandbox_kind")
            reported_str = reported if isinstance(reported, str) else "<missing>"
        else:
            # Malformed (non-object) params: no honest attestation is possible.
            reported_str = "<malformed>"
        if reported_str == declared:
            return

        log.error(
            "sandbox_info_handshake_mismatch",
            plugin_id=self._manifest.plugin_id,
            declared=declared,
            reported=reported_str,
            correlation_id=self._correlation_id,
        )
        # The teardown may itself re-raise a kill failure; the typed mismatch
        # is the security-load-bearing signal the supervisor branches on, so it
        # MUST surface regardless (CR #229 R2 finding-4). ``finally`` raises the
        # mismatch even when ``_quarantine_teardown`` propagates a kill error;
        # that kill error is captured + chained as ``__context__`` so it is not
        # lost from the traceback.
        try:
            await self._quarantine_teardown(reason_base="sandbox_info_handshake_mismatch")
        finally:
            raise SandboxInfoHandshakeMismatch(
                plugin_id=self._manifest.plugin_id,
                declared=declared,
                reported=reported_str,
            )

    async def _quarantine_teardown(self, *, reason_base: str) -> None:
        """SIGKILL + emit the ``plugin.lifecycle.quarantined`` row.

        Shared by the disallowed-method and sandbox_info-mismatch paths. The
        kill runs BEFORE the audit write and the whole sequence is wrapped in
        ``try/finally`` so the row lands even if ``kill()`` raises; the raised
        exception is re-propagated after the row is durable.
        """
        kill_succeeded = False
        kill_exception: BaseException | None = None
        try:
            if self._transport is not None:
                kill_succeeded = await self._transport.kill()
        except BaseException as exc:  # re-raised after audit emit
            kill_exception = exc
        finally:
            await self._audit_writer.append_schema(
                fields=audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
                schema_name="PLUGIN_LIFECYCLE_QUARANTINED_FIELDS",
                event="plugin.lifecycle.quarantined",
                actor_user_id=None,
                subject={
                    "plugin_id": self._manifest.plugin_id,
                    "manifest_subscriber_tier": self._manifest.subscriber_tier,
                    "manifest_version": self._manifest.manifest_version,
                    "sandbox_profile": self._manifest.sandbox_profile,
                    "exit_code": None,
                    "signal": "SIGKILL" if kill_succeeded else None,
                    "restart_count": 0,
                    "breaker_state": "OPEN",
                    "quarantine_reason": (
                        reason_base if kill_succeeded else f"{reason_base} (kill failed)"
                    ),
                    "kill_succeeded": kill_succeeded,
                    "trip_count": 1,
                    "correlation_id": self._correlation_id,
                },
                trust_tier_of_trigger=_AUDIT_TRUST_TIER,
                result="refused",
                cost_estimate_usd=_AUDIT_COST_USD,
                trace_id=self._correlation_id,
            )
            if kill_exception is not None:
                raise kill_exception


__all__ = [
    "AlfredPluginSession",
]
