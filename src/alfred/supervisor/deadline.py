"""Per-orchestrator-action deadline enforcement (spec §10.5).

:class:`DeadlineWrapper` wraps an async callable with
:func:`asyncio.timeout` so the orchestrator's ``handle_user_message``
turn is bounded by a configurable wall-clock budget.

Design pin-points (every one is a Slice-3 review-cycle landmine):

* **Catch only :class:`asyncio.TimeoutError`** (core-002). Python 3.11+
  ``asyncio.timeout()`` converts its OWN internal cancel into
  :class:`TimeoutError` before raising out of the ``async with`` block.
  A genuine :class:`CancelledError` from an operator / system shutdown
  must propagate untouched so the orchestrator's existing
  ``except CancelledError`` arm handles it. NO wall-clock heuristic
  (``elapsed > deadline``) is used to disambiguate — that's how the
  pre-3.11 stdlib lost cancellation signals.
* **No audit side-effect in the wrapper itself** (core-003). Task 12
  wires ``DeadlineWrapper.run`` INSIDE the orchestrator's
  ``session_scope``. On timeout the session is rolled back; a
  session-bound audit row would die with the rollback. The
  ``supervisor.action_timeout`` row therefore lives in the orchestrator,
  which uses an **autocommit** writer (independent session) to flush
  the row before re-raising. ``DeadlineWrapper`` itself stays pure.
* **No fire-and-forget tasks** (err-001 / core-004). The wrapper does
  not call ``asyncio.create_task``; the bounded coroutine runs inside
  the caller's ``TaskGroup`` so subscriber exceptions and operator
  cancels propagate cleanly.
* **``_user_id`` / ``_correlation_id`` are wrapper-internal** (core-005).
  Both are keyword-only parameters consumed by :meth:`DeadlineWrapper.run`
  and explicitly NOT forwarded to ``fn`` via ``**kwargs``. Leading
  underscore in the parameter name is the API contract that distinguishes
  wrapper-internal kwargs from ``fn``-bound kwargs.
* **No swallowed audit-write failures** (err-006). The wrapper has no
  audit code path; the orchestrator's :meth:`_emit_supervisor_timeout_row`
  raises if the autocommit write fails (no ``except: log`` fallback).

The deadline is configured at ``DeadlineWrapper.__init__`` from the
orchestrator's ``Settings.action_deadline_seconds`` (default 30s per
spec §10.5). Hot-reload of the deadline is out of scope for PR-S3-3b;
arch-002 owns reload semantics.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


class DeadlineWrapper:
    """Wrap an async callable with a per-call asyncio.timeout deadline.

    Construction takes the deadline in seconds; each :meth:`run` call
    fires its own ``asyncio.timeout`` block around the supplied
    callable. The instance is stateless beyond the deadline value, so
    one wrapper can be shared across many orchestrator turns without
    coordination.

    Frozen surface — ``deadline_seconds`` is exposed as a read-only
    attribute for observability sub-spans (the orchestrator's
    ``supervisor.action_timeout`` audit row includes it).
    """

    def __init__(self, *, deadline_seconds: float = 30.0) -> None:
        # Public attribute (not ``_deadline_seconds``) so the orchestrator
        # can include it on the timeout audit row without reaching into a
        # private. Spec §10.5 default is 30s; tests can override per-call.
        self.deadline_seconds: float = deadline_seconds

    async def run[R](
        self,
        fn: Callable[..., Awaitable[R]],
        /,
        *args: Any,
        _user_id: str,
        _correlation_id: str,
        **kwargs: Any,
    ) -> R:
        """Call ``fn(*args, **kwargs)`` under a ``deadline_seconds`` deadline.

        ``_user_id`` and ``_correlation_id`` are consumed by the wrapper
        and NEVER forwarded to ``fn``. The leading-underscore naming
        convention pins this — a forwarded ``_user_id`` would either
        crash ``fn`` on a signature mismatch (the common case) or
        silently pollute its kwargs namespace.

        Behaviour matrix:

        +-----------------------------------------+-------------------------------+
        | Trigger                                 | Wrapper re-raises             |
        +=========================================+===============================+
        | ``asyncio.timeout`` fires               | ``asyncio.TimeoutError``      |
        | ``fn`` raises ``CancelledError``        | ``CancelledError`` (unchanged)|
        | ``fn`` raises any other ``Exception``   | that exception (unchanged)    |
        | ``fn`` returns ``R``                    | ``R``                         |
        +-----------------------------------------+-------------------------------+

        The matrix is core-002 verbatim: an external CancelledError
        flies through; only ``asyncio.timeout``'s own conversion to
        TimeoutError is taken as "deadline exceeded". The orchestrator's
        ``except asyncio.TimeoutError`` arm (Task 12) maps that to the
        ``supervisor.action_timeout`` audit row and re-raises
        ``CancelledError`` to trigger the existing rollback arm.

        Args:
            fn: The async callable to wrap. Positional-only via ``/``.
            *args: Positional arguments forwarded to ``fn``.
            _user_id: Wrapper-internal: the per-turn requester slug.
                Reserved for future observability sub-spans (perf §5).
                NOT forwarded to ``fn`` (core-005).
            _correlation_id: Wrapper-internal: the cross-system trace id.
                Same forwarding rule as ``_user_id``.
            **kwargs: Keyword arguments forwarded to ``fn``.

        Returns:
            Whatever ``fn`` returns.

        Raises:
            asyncio.TimeoutError: ``asyncio.timeout`` fired before ``fn``
                completed.
            asyncio.CancelledError: ``fn`` (or anything it awaited)
                raised ``CancelledError``; the wrapper does NOT catch /
                reclassify foreign cancellation.
            BaseException: Anything else ``fn`` raises propagates verbatim.
        """
        # ``_user_id`` and ``_correlation_id`` are intentionally bound but
        # unused in this implementation — observability wiring lands in
        # Slice 4 (perf §5 sub-spans). Binding them to locals (rather
        # than ignoring) keeps the contract observable: a future
        # observability addition reads the binding, not the kwargs.
        _ = _user_id
        _ = _correlation_id

        async with asyncio.timeout(self.deadline_seconds):
            return await fn(*args, **kwargs)


__all__ = ["DeadlineWrapper"]
