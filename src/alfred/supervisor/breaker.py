"""CircuitBreaker — three-state fault isolation for supervised plugins.

State machine (spec §10.2)::

    CLOSED ──(N failures in window)──► OPEN
    OPEN   ──(re-arm: 1h elapsed or operator reset)──► HALF_OPEN
    HALF_OPEN ──(probe succeeds)──► CLOSED
    HALF_OPEN ──(probe fails)──► OPEN

State is persisted to Postgres (``circuit_breakers`` table, migration
0010). Exponential backoff governs HALF_OPEN probes: 5s initial, x2
multiplier, 5min cap (spec §10.2).

Design constraints honoured in this module:

* **No T3 leak in failure metadata.** ``record_failure`` accepts an
  ``exception_type: str`` — the Python *type name* only. Callers MUST NOT
  pass ``str(exc)`` or ``exc.args`` (spec §5.6: subprocess crash messages
  can carry T3 fragments). The audit-row schema constants in
  :mod:`alfred.audit.audit_row_schemas` mirror this contract.
* **No fire-and-forget tasks.** ``_trip`` does NOT spawn a hookpoint
  invocation. Hookpoint emission is the caller's responsibility (Task 9 /
  ``PluginLifecycle.on_crash``) so the call stays inside the
  supervisor's ``TaskGroup`` and exceptions surface (err-001 / core-004).
* **Lost-update safety for persistence.** ``_save_lock`` (an
  ``asyncio.Lock`` per instance) serialises concurrent
  :meth:`CircuitBreaker.save_to_db` callers — see Task 8 docstring.
* **Frozen time injection.** Every method that consults the clock accepts
  a ``now`` keyword so tests run without sleeping and without
  monkeypatching ``datetime.now``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid as _uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from enum import StrEnum
from typing import TYPE_CHECKING

import structlog

from alfred.supervisor.errors import BreakStateError, QuarantinedUnavailable

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_log = structlog.get_logger(__name__)

# Spec §10.2 — failure threshold tuned so transient flakes do not trip
# the breaker but a sustained crash loop does.
_FAILURE_WINDOW_SECONDS: float = 300.0  # 5 minutes
_FAILURE_THRESHOLD: int = 3  # trips after 3 failures in window
_RE_ARM_SECONDS: float = 3600.0  # 1 hour re-arm window (spec §10.6)
_BACKOFF_INITIAL_SECONDS: float = 5.0  # exponential backoff start
_BACKOFF_MULTIPLIER: float = 2.0
_BACKOFF_MAX_SECONDS: float = 300.0  # 5 minutes cap


class BreakerState(StrEnum):
    """Three-state circuit breaker domain (spec §10.2).

    ``StrEnum`` so values round-trip cleanly through the
    ``circuit_breakers.state`` column without manual conversion. The
    domain is pinned at the DB layer by the
    ``ck_circuit_breakers_state`` CHECK constraint (migration 0010).
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Three-state circuit breaker with Postgres persistence (spec §10.2).

    One instance per supervised ``component_id``
    (``Supervisor.get_or_create_breaker`` enforces the
    singleton-per-component invariant). The ``_save_lock`` serialises
    concurrent ``save_to_db`` callers for that one instance — see Task 8.

    Construction takes a ``session_scope`` factory rather than a raw
    session so the breaker can open its own transactional scope when it
    decides to persist (Task 8 wires the orchestrator's session factory
    in). Tests pass ``None`` for the pure state-machine paths that never
    touch the DB.
    """

    def __init__(
        self,
        component_id: str,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None,
        *,
        failure_threshold: int = _FAILURE_THRESHOLD,
        failure_window_seconds: float = _FAILURE_WINDOW_SECONDS,
        re_arm_seconds: float = _RE_ARM_SECONDS,
    ) -> None:
        self.component_id = component_id
        self._session_scope = session_scope
        self._failure_threshold = failure_threshold
        self._failure_window_seconds = failure_window_seconds
        self._re_arm_seconds = re_arm_seconds

        self.state: BreakerState = BreakerState.CLOSED
        self.trip_count: int = 0
        self.last_trip_at: dt.datetime | None = None
        self._recent_failures: list[dt.datetime] = []
        self._backoff_seconds: float = _BACKOFF_INITIAL_SECONDS
        # PR-S3-3a CR-R3 fix pattern: per-instance lock guarantees lost-update
        # safety for concurrent save_to_db callers. Per-instance (not class-level)
        # so unrelated breakers do not block each other.
        self._save_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Failure recording and trip transition (Task 5)
    # ------------------------------------------------------------------

    def record_failure(
        self,
        exception_type: str,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        """Record a plugin failure. Trips CLOSED→OPEN at threshold.

        ``exception_type`` MUST be the Python *type name* only — never
        ``str(exc)`` or ``exc.args``. The subprocess crash message can
        carry T3 fragments (spec §5.6); callers funnel through
        ``type(exc).__name__`` to keep the trip audit row safe to display.

        Sliding window: failures outside ``failure_window_seconds`` are
        dropped each call. Three (configurable) failures inside the window
        trip the breaker. While the breaker is OPEN we no-op — the
        re-arm/reset paths own the transition out of OPEN.
        """
        if self.state == BreakerState.OPEN:
            return  # already tripped; ignore additional failures

        _now = now if now is not None else dt.datetime.now(dt.UTC)
        cutoff = _now - dt.timedelta(seconds=self._failure_window_seconds)
        self._recent_failures = [f for f in self._recent_failures if f > cutoff]
        self._recent_failures.append(_now)

        if len(self._recent_failures) >= self._failure_threshold:
            self._trip(exception_type=exception_type, now=_now)

    def _trip(self, *, exception_type: str, now: dt.datetime) -> None:
        """Internal CLOSED/HALF_OPEN → OPEN transition.

        ``trip_count`` is the cumulative audit counter; it survives reset()
        and load-from-DB. ``last_trip_at`` is the wall-clock at trip time —
        the re-arm path uses it to decide when HALF_OPEN becomes safe.

        This method DOES NOT spawn a hookpoint task. Hookpoint invocation
        is the caller's responsibility (Task 9 / ``PluginLifecycle``); see
        the module docstring for the err-001 / core-004 rationale.
        """
        self.state = BreakerState.OPEN
        self.trip_count += 1
        self.last_trip_at = now
        self._recent_failures.clear()
        _log.warning(
            "supervisor.breaker.tripped",
            component_id=self.component_id,
            trip_count=self.trip_count,
            last_failure_type=exception_type,
        )

    def assert_available(self) -> None:
        """Raise :class:`QuarantinedUnavailable` if the breaker is OPEN.

        Called by ``PluginLifecycle`` before dispatching to a supervised
        plugin. HALF_OPEN is intentionally permissive — the probe must run
        to learn whether the underlying fault has cleared. Only OPEN is
        fully closed to traffic.
        """
        if self.state == BreakerState.OPEN:
            raise QuarantinedUnavailable(self.component_id)

    # ------------------------------------------------------------------
    # OPEN→HALF_OPEN re-arm and probe handlers (Task 6)
    # ------------------------------------------------------------------

    def maybe_rearm(self, *, now: dt.datetime | None = None) -> None:
        """Transition OPEN→HALF_OPEN when the re-arm window has elapsed.

        Called by the supervisor's restart scheduler; the scheduler runs
        this periodically against every OPEN breaker. No-op for CLOSED or
        HALF_OPEN — the protocol only allows re-arm from OPEN.

        If ``last_trip_at`` is None (defensive: should never happen on a
        legitimate trip), we refuse to re-arm and leave the operator's
        ``reset()`` path as the only way out. Pinned by
        ``test_maybe_rearm_noop_when_last_trip_at_is_none``.
        """
        if self.state != BreakerState.OPEN:
            return
        if self.last_trip_at is None:
            return
        _now = now if now is not None else dt.datetime.now(dt.UTC)
        elapsed = (_now - self.last_trip_at).total_seconds()
        if elapsed >= self._re_arm_seconds:
            self.state = BreakerState.HALF_OPEN
            _log.info(
                "supervisor.breaker.half_open",
                component_id=self.component_id,
                elapsed_seconds=elapsed,
            )

    def record_probe_success(self) -> None:
        """HALF_OPEN probe succeeded — close the breaker and reset backoff.

        The backoff counter is reset because the underlying fault has
        cleared; if the next failure cycle tips us back into OPEN we
        start a fresh exponential ramp.
        """
        if self.state != BreakerState.HALF_OPEN:
            raise BreakStateError(
                f"record_probe_success called in state {self.state!r} (expected HALF_OPEN)"
            )
        self.state = BreakerState.CLOSED
        self._recent_failures.clear()
        self._backoff_seconds = _BACKOFF_INITIAL_SECONDS
        _log.info("supervisor.breaker.closed", component_id=self.component_id)

    def record_probe_failure(self, exception_type: str) -> None:
        """HALF_OPEN probe failed — reopen the breaker with doubled backoff.

        Backoff is capped at ``_BACKOFF_MAX_SECONDS`` so a sustained crash
        loop does not push the next re-arm attempt arbitrarily far into
        the future. ``exception_type`` is the Python type name only
        (spec §5.6 — never ``str(exc)``).
        """
        if self.state != BreakerState.HALF_OPEN:
            raise BreakStateError(
                f"record_probe_failure called in state {self.state!r} (expected HALF_OPEN)"
            )
        self._backoff_seconds = min(
            self._backoff_seconds * _BACKOFF_MULTIPLIER, _BACKOFF_MAX_SECONDS
        )
        self._trip(exception_type=exception_type, now=dt.datetime.now(dt.UTC))

    # ------------------------------------------------------------------
    # Operator-triggered reset (Task 7)
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Operator-triggered reset: any state → CLOSED.

        Called by ``Supervisor.reset_breaker()`` after auditing a
        ``supervisor.breaker.reset`` row. ``trip_count`` is NOT cleared —
        it is a cumulative audit counter that must survive operator
        intervention so dashboards can show "this component has tripped N
        times across its lifetime."

        Recent-failure window and backoff are cleared so the breaker
        behaves identically to a freshly-constructed CLOSED breaker after
        reset (pinned by ``test_reset_then_failures_can_trip_fresh``).
        Otherwise stale window entries would immediately re-trip on the
        next failure and defeat the operator override.

        No raise from any source state — including CLOSED (silent no-op).
        Hookpoint emission is the caller's responsibility (see module
        docstring).
        """
        self.state = BreakerState.CLOSED
        self._recent_failures.clear()
        self._backoff_seconds = _BACKOFF_INITIAL_SECONDS
        _log.info("supervisor.breaker.reset", component_id=self.component_id)

    # ------------------------------------------------------------------
    # Postgres persistence (Task 8)
    # ------------------------------------------------------------------

    async def load_from_db(
        self,
        session: AsyncSession,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        """Load persisted state from Postgres at supervisor startup.

        Spec §10.6 flap protection: if the persisted state is OPEN and
        ``last_trip_at`` is < 1h ago, we stay OPEN on load. If
        ``last_trip_at`` is older than the re-arm window, we transition
        to HALF_OPEN — same logic as the runtime ``maybe_rearm``.

        A missing row (first startup or post-truncate) leaves the
        defaults from ``__init__`` untouched — CLOSED, trip_count=0.

        An out-of-domain state column raises :class:`BreakStateError`.
        The DB-side CHECK constraint forbids this; we re-pin it here to
        defend against manual column edits or future schema drift.
        """
        # Local import: defers the alfred.memory.models load so module
        # import-time on alfred.supervisor stays free of the memory layer
        # (memory.models pulls in SQLAlchemy ORM machinery the rest of
        # the supervisor surface doesn't need).
        from alfred.memory.models import CircuitBreakerState as _Model

        row: _Model | None = await session.get(_Model, self.component_id)
        if row is None:
            return  # new breaker; defaults already CLOSED

        self.trip_count = row.trip_count
        self.last_trip_at = row.last_trip_at
        match row.state:
            case BreakerState.CLOSED.value:
                self.state = BreakerState.CLOSED
            case BreakerState.OPEN.value:
                self.state = BreakerState.OPEN
                # Apply re-arm check using wall-clock at load (spec §10.6).
                self.maybe_rearm(now=now)
            case BreakerState.HALF_OPEN.value:
                self.state = BreakerState.HALF_OPEN
            case _:
                raise BreakStateError(
                    f"load_from_db: unknown state value {row.state!r} for "
                    f"component_id={self.component_id!r}"
                )

    async def save_to_db(self, session: AsyncSession) -> None:
        """Persist current state to Postgres. Call after every transition.

        Uses ``session.merge`` for upsert semantics (INSERT or UPDATE by
        primary key). The merged row carries the live-state surface
        (state, trip_count, last_trip_at).

        **Lost-update safety (PR-S3-3a CR-R3 fix).** Two coroutines
        calling ``save_to_db`` on the same instance — e.g. a crash
        handler and a manual reset — can interleave their read-modify-
        write and lose a trip_count increment. The per-instance
        ``_save_lock`` serialises all writes for that instance. Because
        ``CircuitBreaker`` is a singleton per ``component_id``
        (``Supervisor.get_or_create_breaker`` — Task 19), the
        per-instance lock provides full correctness inside the single
        event loop AlfredOS runs on. A future multi-process supervisor
        would escalate to ``SELECT … FOR UPDATE`` on the row; out of
        scope for Slice 3.

        ``last_failure_type``, ``breaker_state`` (captured-at-trip), and
        ``correlation_id`` are NOT written here — the trip path
        (``Supervisor.on_crash`` / ``PluginLifecycle``) sets those on the
        row directly via the audit-row schema. We carry only the
        live-state surface that the breaker owns.

        Migration 0010 declares no ``updated_at`` column on
        ``circuit_breakers`` — Postgres records modify time via the WAL,
        not as a row attribute. The integration test verifies the
        write-then-read round-trip.
        """
        # Local import: defers the alfred.memory.models load so module
        # import-time on alfred.supervisor stays free of the memory layer
        # (memory.models pulls in SQLAlchemy ORM machinery the rest of
        # the supervisor surface doesn't need).
        from alfred.memory.models import CircuitBreakerState as _Model

        async with self._save_lock:
            row = _Model(
                component_id=self.component_id,
                state=self.state.value,
                trip_count=self.trip_count,
                last_trip_at=self.last_trip_at,
            )
            await session.merge(row)


# ---------------------------------------------------------------------------
# Hookpoint invocation helpers (Task 9) — err-001 / core-004
# ---------------------------------------------------------------------------
#
# Both helpers are intentionally **module-level coroutines** rather than
# methods on :class:`CircuitBreaker`. The breaker's state machine is a pure
# domain object (no I/O, no awaits); the hookpoint helpers do I/O (audit
# emit via the dispatcher's sink) and so live one layer above the state
# machine. Keeping them at module scope:
#
# * preserves the breaker's purity for the state-machine tests
#   (``test_breaker_state_machine.py``), which never sleep and never touch
#   the registry;
# * lets the supervisor/plugin-lifecycle code call them with no instance
#   handle when the breaker singleton is resolved elsewhere
#   (``Supervisor.get_or_create_breaker`` — Task 19);
# * removes the temptation to spawn ``asyncio.create_task(self._invoke(...))``
#   from inside ``_trip`` — the helpers are ``async`` and must be awaited by
#   the caller's ``TaskGroup`` (err-001 / core-004).


async def invoke_breaker_tripped_hookpoint(
    *,
    component_id: str,
    trip_count: int,
    last_failure_type: str,
) -> None:
    """Invoke ``supervisor.breaker.tripped`` via the hook dispatcher.

    Called by :class:`alfred.supervisor.plugin_lifecycle.PluginLifecycle`
    after :meth:`CircuitBreaker.record_failure` transitions to OPEN. The
    coroutine is awaited inside the caller's :class:`asyncio.TaskGroup` so
    subscriber exceptions surface and chain timeouts honour the supervisor's
    backstop. Fire-and-forget (``asyncio.get_running_loop().create_task``)
    is forbidden by err-001 / core-004 — every Slice-3 review cycle has
    re-pinned the rule.

    Args:
        component_id: The breaker's logical component (plugin_id, dispatch
            target, etc.). Round-trips into the audit row's ``component_id``
            field.
        trip_count: Cumulative trip count after the state change. Survives
            ``reset()`` (operator-triggered) so the row reflects lifetime
            count, not since-last-reset.
        last_failure_type: Python exception type name only — NEVER
            ``str(exc)`` or ``exc.args``. Subprocess crash traces can carry
            T3 fragments (spec §5.6); callers MUST funnel through
            ``type(exc).__name__``.

    Hookpoint metadata (registered by ``Supervisor.__init__`` — Task 20):
        - ``subscribable_tiers``: system + operator (operator dashboards can
          observe; no user-plugin subscribers).
        - ``refusable_tiers``: empty — the breaker has already tripped; a
          refusal would not roll back the state machine.
        - ``fail_closed=False`` — observability stage; a crashing observer
          must not stall the supervisor's restart loop.

    Mirrors :data:`alfred.audit.audit_row_schemas.SUPERVISOR_BREAKER_TRIPPED_FIELDS`:
    callers that build the audit row from the same fields keep the audit
    schema and the hookpoint subject in lock-step.
    """
    # Deferred import: ``alfred.hooks.invoke`` re-exports through
    # ``alfred.hooks.registry`` which in turn imports ``alfred.security`` —
    # eagerly pulling that at ``alfred.supervisor.breaker`` import time would
    # widen the import graph for the pure state-machine tests that do not
    # need it. Local import keeps the state-machine path free of the hook
    # subsystem when the helper is never called.
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke

    # core-005 / freshness — each invocation mints its own correlation id so
    # concurrent crash handlers do not collapse onto a single audit row.
    correlation_id = str(_uuid.uuid4())
    ctx: HookContext[dict[str, object]] = HookContext(
        action_id="supervisor.breaker.tripped",
        hookpoint="supervisor.breaker.tripped",
        input={
            "component_id": component_id,
            "trip_count": trip_count,
            "last_failure_type": last_failure_type,
            "breaker_state": BreakerState.OPEN.value,
            "correlation_id": correlation_id,
        },
        correlation_id=correlation_id,
        kind="post",
    )
    # core-004 — ``invoke``'s first positional is ``name``; never
    # ``hookpoint=`` keyword (that arg name does not exist on ``invoke``).
    await invoke("supervisor.breaker.tripped", ctx, kind="post", fail_closed=False)


async def invoke_breaker_reset_hookpoint(
    *,
    component_id: str,
    old_state: str,
    new_state: str,
    trip_count: int,
    operator_user_id: str,
) -> None:
    """Invoke ``supervisor.breaker.reset`` via the hook dispatcher.

    Called by ``Supervisor.reset_breaker()`` (Task 20) after the breaker's
    in-memory transition + ``save_to_db`` round-trip. ``old_state`` MUST
    name the pre-reset state — a no-op CLOSED→CLOSED reset is auditable but
    visibly distinct from a true OPEN→CLOSED rescue. ``trip_count`` is the
    cumulative counter; ``reset()`` does not clear it so the row carries
    the lifetime count.

    Hookpoint metadata (Task 20):
        - ``subscribable_tiers``: system + operator only.
        - ``refusable_tiers``: empty — reset is an operator override; a
          refusal would defeat the override.
        - ``fail_closed=False``.

    Mirrors :data:`alfred.audit.audit_row_schemas.SUPERVISOR_BREAKER_RESET_FIELDS`.
    """
    # See ``invoke_breaker_tripped_hookpoint`` for the deferred-import
    # rationale.
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke

    correlation_id = str(_uuid.uuid4())
    ctx: HookContext[dict[str, object]] = HookContext(
        action_id="supervisor.breaker.reset",
        hookpoint="supervisor.breaker.reset",
        input={
            "component_id": component_id,
            "old_state": old_state,
            "new_state": new_state,
            "trip_count": trip_count,
            "operator_user_id": operator_user_id,
            "correlation_id": correlation_id,
        },
        correlation_id=correlation_id,
        kind="post",
    )
    await invoke("supervisor.breaker.reset", ctx, kind="post", fail_closed=False)


__all__ = [
    "BreakerState",
    "CircuitBreaker",
    "invoke_breaker_reset_hookpoint",
    "invoke_breaker_tripped_hookpoint",
]
