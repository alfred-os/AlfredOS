"""DeadlineWrapper tests (Task 11) — pure timing wrapper, no audit side-effects.

Spec §10.5 mandates a per-action deadline around the orchestrator's
``handle_user_message`` body. The wrapper is intentionally minimal:

* :class:`asyncio.timeout` is the underlying mechanism. Python 3.11+
  converts the internal cancel into :class:`asyncio.TimeoutError` before
  it escapes the ``async with`` block, so the orchestrator's existing
  ``except CancelledError`` arm is NOT a fallback for the timeout case.
* The wrapper does NOT touch the audit log. Emit semantics live in the
  orchestrator (Task 12) so the timeout row can land OUTSIDE the
  rolled-back session (core-003: session-bound audit row dies with the
  rollback) via an autocommit writer.
* ``_user_id`` and ``_correlation_id`` are consumed by the wrapper (for
  future observability wiring) and NEVER forwarded to ``fn`` (core-005).

Test discipline:

* ``asyncio.sleep`` is the only time-based primitive. The tests fire
  ``deadline_seconds=0.001`` to force timeout deterministically.
* No DB, no Postgres, no audit machinery — DeadlineWrapper has no such
  dependencies.
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.mark.asyncio
async def test_deadline_fires_raises_timeout_error() -> None:
    """When ``asyncio.timeout`` fires, ``DeadlineWrapper.run`` re-raises ``TimeoutError``.

    Pin: never ``CancelledError`` (core-002). The orchestrator's
    existing ``except CancelledError`` arm handles operator/system
    cancellation; the timeout path is a distinct arm.
    """
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper(deadline_seconds=0.001)

    async def slow_fn() -> str:
        await asyncio.sleep(10)
        return "done"

    with pytest.raises(asyncio.TimeoutError):
        await wrapper.run(slow_fn, _user_id="user-1", _correlation_id="corr-1")


@pytest.mark.asyncio
async def test_operator_cancel_propagates_cancelled_error_not_timeout() -> None:
    """Operator-initiated ``CancelledError`` passes through DeadlineWrapper unchanged.

    Pin: core-002 — the wrapper does NOT swallow / reclassify a real
    cancellation as a timeout. ``asyncio.timeout`` only converts to
    ``TimeoutError`` when its OWN internal cancel fires; a foreign
    ``CancelledError`` flies straight through.
    """
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper(deadline_seconds=30.0)

    async def cancellable_fn() -> str:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await wrapper.run(cancellable_fn, _user_id="u", _correlation_id="c")


@pytest.mark.asyncio
async def test_deadline_user_id_not_forwarded_to_fn() -> None:
    """``_user_id`` / ``_correlation_id`` are consumed by the wrapper, not forwarded.

    Pin: core-005 — leaking these to ``fn`` would either crash
    ``fn(**kwargs)`` on a signature mismatch or silently pollute its
    keyword namespace. The wrapper signature reserves them with the
    leading-underscore convention.
    """
    from alfred.supervisor.deadline import DeadlineWrapper

    received_kwargs: dict[str, object] = {}

    async def recorder(**kw: object) -> str:
        received_kwargs.update(kw)
        return "ok"

    wrapper = DeadlineWrapper(deadline_seconds=5.0)
    await wrapper.run(recorder, x=1, _user_id="u", _correlation_id="c")
    assert "_user_id" not in received_kwargs
    assert "_correlation_id" not in received_kwargs
    assert received_kwargs == {"x": 1}


@pytest.mark.asyncio
async def test_deadline_success_returns_result() -> None:
    """A fast ``fn`` returns its result unchanged through the wrapper."""
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper(deadline_seconds=5.0)

    async def fast_fn() -> str:
        return "done"

    result = await wrapper.run(fast_fn, _user_id="u", _correlation_id="c")
    assert result == "done"


@pytest.mark.asyncio
async def test_deadline_forwards_positional_args() -> None:
    """Positional args are forwarded to ``fn`` verbatim.

    The wrapper's signature uses ``/`` to split ``fn`` from the rest of
    the args — positional pass-through is essential for the orchestrator
    wiring (Task 12) which passes ``session`` as the first positional to
    ``_handle_turn``.
    """
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper(deadline_seconds=5.0)

    async def sum_fn(a: int, b: int, *, c: int) -> int:
        return a + b + c

    result = await wrapper.run(sum_fn, 1, 2, c=3, _user_id="u", _correlation_id="r")
    assert result == 6


@pytest.mark.asyncio
async def test_deadline_default_seconds_is_thirty() -> None:
    """The production default is 30s (spec §10.5)."""
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper()
    assert wrapper.deadline_seconds == 30.0


@pytest.mark.asyncio
async def test_deadline_propagates_fn_exception_unchanged() -> None:
    """An exception raised by ``fn`` (not TimeoutError) propagates verbatim.

    The wrapper is not an exception handler — it adds the deadline and
    nothing else. A ``ValueError`` from ``fn`` MUST propagate so the
    orchestrator's existing error-handling arms can react.
    """
    from alfred.supervisor.deadline import DeadlineWrapper

    wrapper = DeadlineWrapper(deadline_seconds=5.0)

    async def raises_fn() -> str:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await wrapper.run(raises_fn, _user_id="u", _correlation_id="c")
