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

import hashlib
import re
import uuid
from typing import TYPE_CHECKING, Final

import structlog

from alfred.audit import audit_row_schemas
from alfred.audit.log import AuditWriter
from alfred.hooks.capability import CapabilityGate
from alfred.plugins.errors import (
    ManifestError,
    PluginError,
    SandboxInfoHandshakeMismatch,
)
from alfred.plugins.manifest import PluginManifest, parse_manifest

if TYPE_CHECKING:
    from collections.abc import Mapping

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
    ) -> None:
        """Internal: prefer ``await AlfredPluginSession.create(manifest_raw=...)``.

        Takes an already-parsed :class:`PluginManifest` so this is pure
        synchronous state init — no audit emits, no I/O. The
        :meth:`create` factory handles the parse and the awaited
        ``plugin.lifecycle.load_refused`` emit on failure.
        """
        self._audit_writer = audit_writer
        self._gate = gate
        self._transport = transport
        self._manifest: PluginManifest = manifest
        self._handshake_complete = False
        self._correlation_id = correlation_id or str(uuid.uuid4())

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
        self, method: str, params: Mapping[str, object] | None = None
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

        For any other method the call is a no-op; routing to the real
        dispatch loop is the supervisor's job.
        """
        if method == "sandbox_info":
            await self._verify_sandbox_info(params or {})
            return
        if method not in _DISALLOWED_POST_HANDSHAKE_METHODS:
            return

        log.error(
            "post_handshake_disallowed_method",
            plugin_id=self._manifest.plugin_id,
            method=method,
            correlation_id=self._correlation_id,
        )
        await self._quarantine_teardown(reason_base="protocol_violation")

    async def _verify_sandbox_info(self, params: Mapping[str, object]) -> None:
        """Compare the plugin-reported sandbox kind against the manifest (arch-3).

        A missing or mismatched ``effective_sandbox_kind`` is a plugin that
        will not (or cannot) honestly attest its isolation — quarantine the
        session and re-raise :class:`SandboxInfoHandshakeMismatch`.
        """
        declared = self._manifest.sandbox.kind
        reported = params.get("effective_sandbox_kind")
        reported_str = reported if isinstance(reported, str) else "<missing>"
        if reported_str == declared:
            return

        log.error(
            "sandbox_info_handshake_mismatch",
            plugin_id=self._manifest.plugin_id,
            declared=declared,
            reported=reported_str,
            correlation_id=self._correlation_id,
        )
        await self._quarantine_teardown(reason_base="sandbox_info_handshake_mismatch")
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
