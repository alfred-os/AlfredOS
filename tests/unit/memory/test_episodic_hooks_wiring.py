"""Characterization tests for :meth:`EpisodicMemory.record`'s persistence.

Slice-2.5 PR-B Task 2. These tests pin the *golden row* — the exact
shape and side-effects of today's ``record`` — BEFORE Task 2 refactors
its body into a private ``_persist`` helper and BEFORE Task 4-5 wire
the hookpoints through :func:`alfred.hooks.invoking`.

The plan calls these "characterization tests": they intentionally pass
against both the pre-refactor body (a single inline ``Episode(...) +
add + flush`` block) AND the post-refactor body (``inp = EpisodicRecord
Input(...); await self._persist(inp)``). Their job is to fail loudly
if any later commit drifts the persisted-row shape, the call count,
the awaited-once flush, or the "no other session method touched"
invariant the caller's ``session_scope`` depends on.

Four invariants pinned:

* **Exactly one ``Episode`` is added per ``record`` call.** A bug where
  the refactor double-counts (e.g. a leftover inline ``add`` plus a new
  ``_persist`` ``add``) trips immediately.
* **All 10 input fields land on the persisted ``Episode`` verbatim.**
  Catches a field-mapping regression — e.g. a refactor that drops
  ``persona_id`` because it has a default — without needing to read the
  ``Episode(...)`` constructor at review time.
* **``session.flush()`` is awaited exactly once.** Pins the
  "one-flush-per-record" contract the caller relies on for ordered
  visibility before the next read.
* **No other session method (``commit``, ``rollback``, ``execute``,
  ``begin``) is invoked.** ``record`` is a writer; transactional
  control belongs to the caller's ``session_scope``. Catches a
  refactor that "helpfully" adds a commit and breaks atomicity across
  multi-record turns.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import Episode

# Representative kwargs covering every parameter — including non-default
# values for the six fields with defaults — so the "fields match input"
# assertions exercise the real mapping, not just whatever the defaults
# happen to be today.
_RECORD_KWARGS: dict[str, object] = {
    "user_id": "operator",
    "role": "user",
    "content": "hello alfred",
    "trust_tier": "T2",
    "tokens_in": 7,
    "tokens_out": 13,
    "cost_usd": 0.000_123,
    "persona": "alfred",
    "persona_id": "alfred",
    "language": "en-US",
}


def _mock_session() -> AsyncMock:
    """AsyncSession surrogate matching :mod:`tests.unit.memory.test_episodic`:
    ``add`` is sync (override the AsyncMock default), ``flush`` / ``execute``
    stay async. Keeping the helper local rather than importing keeps the
    characterization isolated — if the canonical mock helper changes its
    shape, this test still pins today's behaviour.
    """
    session = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.mark.asyncio
class TestRecordPersistsGoldenRow:
    """Locks the persistence side-effects of ``record`` so Task 2's
    extraction of ``_persist`` and Task 4-5's hook wiring are provably
    behaviour-preserving."""

    async def test_record_adds_exactly_one_episode(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert session.add.call_count == 1
        added = session.add.call_args_list[0].args[0]
        assert isinstance(added, Episode)

    async def test_record_maps_every_input_field_onto_episode(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        added: Episode = session.add.call_args_list[0].args[0]
        # Iterate the kwargs rather than spelling each assertion out so
        # adding an 11th kwarg to ``record`` + ``Episode`` is covered
        # the moment ``_RECORD_KWARGS`` is updated. The drift-guard in
        # ``test_episodic_record_input.py`` already enforces that the
        # carrier's field list mirrors ``record``'s signature, so the
        # set of names traversed here cannot silently shrink.
        for field_name, expected_value in _RECORD_KWARGS.items():
            assert getattr(added, field_name) == expected_value, (
                f"field {field_name!r} did not land on the persisted Episode"
            )

    async def test_record_awaits_flush_exactly_once(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        session.flush.assert_awaited_once()

    async def test_record_touches_no_other_session_method(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # Transactional control (``commit`` / ``rollback`` / ``begin``)
        # belongs to the caller's ``session_scope``. ``execute`` is the
        # read path and has no business firing on a write. AsyncMock
        # records ``await_count`` for awaitable methods; ``call_count``
        # for sync. Both must be zero.
        assert session.commit.await_count == 0
        assert session.rollback.await_count == 0
        assert session.execute.await_count == 0
        assert session.begin.call_count == 0
