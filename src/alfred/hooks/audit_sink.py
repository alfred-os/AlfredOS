"""Hook subsystem audit sink — spec §0 + PR-A Task 5.

The audit sink is the Protocol seam between the hook dispatcher and the
audit-row writer. Every refusal, every chain timeout, every subscriber
error, every error-suppressed deny, every unauthorized-tier refusal,
every reentry-bypass event, and every registration-time tier rejection
flows through ``await sink.emit(...)`` so audit attribution stays
uniform across the seven hook-trace event kinds.

Two pieces ship this slice:

* :class:`AuditSink` — a ``@runtime_checkable`` :class:`typing.Protocol`
  describing the single seam every sink implementation honours. The
  signature is verbatim from spec §0 — fully keyword-only ``emit`` with
  ``event``, ``correlation_id``, and a ``Mapping[str, object]`` of
  ``fields``. PR-B's dispatcher type-narrows against this Protocol; the
  real DB-backed sink ships in PR-B without any source changes here.
* :class:`StructlogAuditSink` — the PR-A default. Binds ``event``,
  ``correlation_id``, and the ``fields`` mapping onto an INJECTED
  structlog logger and ``.info(...)`` 's a hook-trace row. NO database
  write — that's arch-001 — PR-B brings the real
  :class:`alfred.audit.log.AuditWriter`-backed sink.

The seven ``HOOKS_*`` module constants are the canonical audit-row
event IDENTIFIERS the dispatcher and the test suite share by import.
They are NOT operator-facing display strings (they're never rendered
to a TUI / Discord operator), so they live as plain ``Final[str]``
constants — no catalog key, no :func:`alfred.i18n.t` wrapping.

Hard-rule invariants pinned by ``tests/unit/hooks/test_audit_sink.py``:

* **CLAUDE.md hard rule #1 + #2** — never log secrets; the redactor is
  on every log path. The default sink uses ``structlog.get_logger`` —
  the leaf-redactor processor configured by
  :func:`alfred.cli._bootstrap.configure_logging` runs in front of every
  emission. A spy-logger fixture proves the call shape; a real
  redactor-chain fixture proves the redaction end-to-end (``sk-…`` shape
  → ``[REDACTED:api-key-shape]``).
* **CLAUDE.md hard rule #7** — no silent failures. ``emit`` is async
  and lets exceptions propagate; no ``try/except: pass`` wraps the
  ``.info(...)`` call. The dispatcher decides how to react to a failed
  audit write (PR-B).
* **arch-001** — structlog-only default; no DB import. The test module
  AST-scans this file's imports to enforce the "no
  ``alfred.audit.log`` / ``AuditWriter`` / ``sqlalchemy`` / ``asyncpg``"
  invariant at every CI run.
* **Frozen + slots** — the sink is a frozen dataclass with ``slots``
  so the dispatcher's hot path doesn't pay for ``__dict__`` allocation
  per instance, and the injected logger handle cannot be swapped after
  construction (configuration is the constructor's job).
* **Keyword-only** ``emit`` — the ``*`` after ``self`` is verbatim spec
  §0. Mypy / pyright reject positional misuse statically; the test
  suite pins a ``TypeError`` at runtime as the belt-and-braces guard.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

# ──────────────────────────────────────────────────────────────────────
# Event-name identifiers — spec §0 verbatim
# ──────────────────────────────────────────────────────────────────────
#
# These are audit-row event IDENTIFIERS the dispatcher uses to key
# hook-trace rows in the audit log. They are NOT operator-facing
# display strings — never rendered to a user / operator — so they live
# as ``Final[str]`` constants, not catalog keys. Centralising them here
# means the dispatcher (PR-B's ``_run_chain``) and the test suite share
# one source of truth; a typo in an event name caught at one site is
# caught at every site.

HOOKS_REFUSAL: Final[str] = "hooks.refusal"
"""Audit-row event id for a ``HookRefusal`` raised by a ``pre`` hook."""

HOOKS_CHAIN_TIMEOUT: Final[str] = "hooks.chain_timeout"
"""Audit-row event id for the dispatcher's chain-level timeout deny."""

HOOKS_SUBSCRIBER_ERROR: Final[str] = "hooks.subscriber_error"
"""Audit-row event id for a non-refusal exception raised by a subscriber."""

HOOKS_ERROR_SUPPRESSED: Final[str] = "hooks.error_suppressed"
"""Audit-row event id for a deny suppressed because the action body
already failed (``error`` stage)."""

HOOKS_UNAUTHORIZED_REFUSAL: Final[str] = "hooks.unauthorized_refusal"
"""Audit-row event id for a refusal raised by a hook whose declared
trust tier the capability gate denied."""

HOOKS_REENTRY_BYPASS: Final[str] = "hooks.reentry_bypass"
"""Audit-row event id for a re-entrant dispatch where the inner chain
was bypassed (the dispatcher detected the loop and refused to recurse)."""

HOOKS_TIER_REJECTED: Final[str] = "hooks.tier_rejected"
"""Audit-row event id for any #119 / spec §6.2 tier-allow-list refusal
OR any dispatch-time publisher-side meta drift.

Two emit sites — the same event id covers both because both shapes
are the same operational signal ("a publisher / subscriber
contract was violated against the declared hookpoint metadata"). The
``drift_at`` and ``drift_kind`` fields on the row distinguish the
specific arm so operators can grep and alert per-shape.

* :meth:`alfred.hooks.registry.HookRegistry.register` — **register
  time**. Emitted when the publisher-declared
  :attr:`HookpointMeta.subscribable_tiers` rejects the subscriber's
  requested ``tier``. The row carries the subscriber name and the
  declared allow-list; no ``drift_at`` / ``drift_kind`` because the
  refusal happened before any dispatch.
* :func:`alfred.hooks.invoke._enforce_subscribable_tiers` —
  **dispatch time** (#119 review Group I, CR cycle-1 MAJ-2). Emitted
  when the publisher's invoke-time arg drifts from the declared
  :class:`HookpointMeta` on any of the three fields
  (``subscribable_tiers``, ``refusable_tiers``, ``fail_closed``) OR
  when the hookpoint is undeclared under
  ``strict_declarations=True``. The row carries ``drift_at="dispatch"``
  plus a ``drift_kind`` field:

  - ``"subscribable_tiers"`` — declared and invoked sets differ.
  - ``"refusable_tiers"`` — same, for the refusal allow-list.
  - ``"fail_closed"`` — declared and invoked policy bits differ
    (highest-blast — silently disarms the timeout policy on a
    security stage).
  - ``"undeclared_hookpoint"`` — strict mode + no
    :meth:`register_hookpoint` declaration. An internal
    inconsistency: register-time enforcement should have caught
    this.

CLAUDE.md hard rule #7 — the audit row is the loud-failure escape;
the :class:`alfred.hooks.errors.HookError` raise is the immediate
signal to the caller, the audit row is the durable attribution
operators can grep.
"""


# ──────────────────────────────────────────────────────────────────────
# Protocol seam — spec §0 verbatim
# ──────────────────────────────────────────────────────────────────────


@runtime_checkable
class AuditSink(Protocol):
    """Structural Protocol every hook audit sink implementation honours.

    A sink's only job is to persist a hook-trace row for a given event
    identifier. The Protocol is ``@runtime_checkable`` so dispatcher
    code (PR-B's ``_run_chain``) can :func:`isinstance`-narrow without
    a concrete base class — the PR-A :class:`StructlogAuditSink`,
    PR-B's DB-backed sink, and every test fixture sink all satisfy the
    same structural seam.

    The keyword-only signature is part of the public contract: the
    ``*`` after ``self`` makes ``event``, ``correlation_id``, and
    ``fields`` impossible to pass positionally. A future ``async def
    emit(self, event, correlation_id, fields)`` would silently re-order
    audit attribution at every call site; the keyword-only seam pins
    the call shape.

    Every implementation MUST preserve:

    * the ``async def`` shape (the Protocol's method is async),
    * the ``*,`` discipline (all parameters keyword-only),
    * the ``-> None`` return (the sink does not return a value to the
      dispatcher; failure surfaces as a raised exception).

    Operational contract (load-bearing for the sync-from-async bridge
    in :meth:`alfred.hooks.registry.HookRegistry._emit_sync`):

    * **Fast** — implementations MUST keep ``emit`` p99 cost below
      500 ms. The register-time sync-from-async bridge bounds the
      driving thread's join at 500 ms; a sink that routinely exceeds
      the bound trips the structlog fallback and surfaces in the
      ``alfred.hooks.audit_fallback`` channel as a
      ``reason=sink_emit_timeout`` row. Persistent fallbacks are an
      ALERT — the primary sink is either backed up or wedged.
    * **Thread-safe** — the register-time bridge may drive ``emit``
      from a fresh thread that owns its own asyncio loop. Any shared
      state inside the sink (DB connection pools, in-process queues,
      counters) must be safe under concurrent access from the
      dispatcher's main loop AND from short-lived sync-from-async
      threads. Slice-3's future grant-gate runtime-register-from-
      async path inherits the same expectation.
    """

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None: ...


# ──────────────────────────────────────────────────────────────────────
# Default structlog-only sink — PR-A
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StructlogAuditSink:
    """PR-A default :class:`AuditSink` — writes one structlog row per emit.

    The injected ``logger`` is the project's structlog handle (any value
    returned by :func:`structlog.get_logger`). Slice-2.5 ships the
    leaf-redactor processor chain configured by
    :func:`alfred.cli._bootstrap.configure_logging` — that chain runs
    BEFORE the renderer at every emission, so a secret-shaped value
    inside ``fields`` is masked to ``[REDACTED:api-key-shape]`` (or the
    broker's stage-1 sentinel) before the hook-trace row leaves the
    process.

    arch-001: this sink has NO database write. PR-B introduces the
    persistent :class:`alfred.audit.log.AuditWriter`-backed sink behind
    the same :class:`AuditSink` Protocol — the dispatcher swaps the
    concrete instance at construction time, no source change here.

    The constructor is the ONLY configuration surface: the dataclass is
    ``frozen=True`` so the injected logger handle cannot be reassigned
    after construction. ``slots=True`` removes per-instance ``__dict__``
    allocation — the sink flies through the dispatcher's hot path.

    Args:
        logger: Any structlog bound logger handle. Typed ``Any`` because
            structlog's public type for the value returned by
            :func:`structlog.get_logger` is ``BindableLogger`` in some
            versions and ``BoundLoggerLazyProxy`` in others; pinning a
            single concrete alias would couple this sink to a
            structlog-version-specific name. The Protocol contract
            (``.info(event, **fields)``) is what we rely on, not the
            concrete type.
    """

    logger: Any

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        """Persist a hook-trace row via the injected structlog logger.

        Binds ``correlation_id`` and every key in ``fields`` as kwargs
        on the structlog event so the renderer (JSON or otherwise)
        surfaces them as first-class row attributes. ``event`` is the
        positional log identifier — by structlog convention this is the
        ``event`` key in the rendered row.

        The redactor chain configured in
        :func:`alfred.cli._bootstrap.configure_logging` runs in front
        of the renderer, so any secret-shaped value in ``fields`` is
        masked before the row is rendered. CLAUDE.md hard rules #1 +
        #2 — never log secrets.

        Exceptions raised by the logger propagate — no
        ``try/except: pass`` here. The dispatcher (PR-B's
        ``_run_chain``) decides how to surface an audit-write failure.
        CLAUDE.md hard rule #7 — no silent failures in security paths.

        Args:
            event: One of the ``HOOKS_*`` audit-row event identifiers
                defined in this module. The dispatcher passes the
                event-name constant; the sink does not validate
                membership (a future event added here is picked up
                without a code change in the sink).
            correlation_id: Cross-system trace correlation id, bound
                onto the structlog event as a row attribute.
            fields: Free-form mapping of additional row attributes.
                Bound as kwargs on the structlog event. The redactor
                chain mass-scans every leaf string.
        """
        # ``Mapping`` is iterated cheaply via ``**`` because structlog's
        # ``.info`` accepts arbitrary kwargs; a stray non-string key
        # in ``fields`` is a caller bug surfaced at the structlog call
        # site (which is the right place — the audit sink does not
        # enforce a schema beyond the Protocol's typed signature).
        self.logger.info(event, correlation_id=correlation_id, **fields)
